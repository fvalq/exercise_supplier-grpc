package pt.tecnico.supplier;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

import com.google.type.Money;

import io.grpc.stub.StreamObserver;
import pt.tecnico.supplier.domain.Supplier;
import pt.tecnico.supplier.grpc.Product;
import pt.tecnico.supplier.grpc.ProductsRequest;
import pt.tecnico.supplier.grpc.ProductsResponse;
import pt.tecnico.supplier.grpc.SignedResponse;
import pt.tecnico.supplier.grpc.SupplierGrpc;
import pt.tecnico.supplier.grpc.SignedResponse;
import pt.tecnico.supplier.grpc.Signature;	
import javax.crypto.spec.SecretKeySpec;
import static javax.xml.bind.DatatypeConverter.printHexBinary;

import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import com.google.protobuf.ByteString;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

public class SupplierServiceImpl extends SupplierGrpc.SupplierImplBase {
	// // public static SecretKeySpec readKey(String resourcePathName) throws Exception {
	// // 	System.out.println("Reading key from resource " + resourcePathName + " ...");
		
	// // 	InputStream fis = Thread.currentThread().getContextClassLoader().getResourceAsStream(resourcePathName);
	// // 	byte[] encoded = new byte[fis.available()];
	// // 	fis.read(encoded);
	// // 	fis.close();
		
	// // 	System.out.println("Key:");
	// // 	System.out.println(printHexBinary(encoded));
	// // 	SecretKeySpec keySpec = new SecretKeySpec(encoded, "AES");

	// // 	return keySpec;
	// // }
	private static byte[] readFile(String path) throws FileNotFoundException, IOException {
		InputStream fis = Thread.currentThread().getContextClassLoader().getResourceAsStream(path);
		byte[] content = new byte[fis.available()];
		fis.read(content);
		fis.close();
		return content;
	}

	public static PrivateKey readKey(String resourcePathName) throws Exception {
		System.out.println("Reading private key from file " + resourcePathName + " ...");
		byte[] privEncoded = readFile(resourcePathName);

		PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privEncoded);
		KeyFactory keyFacPriv = KeyFactory.getInstance("RSA");
		PrivateKey priv = keyFacPriv.generatePrivate(privSpec);
		return priv;
	}

	/**
	 * Set flag to true to print debug messages. The flag can be set using the
	 * -Ddebug command line option.
	 */
	private static final boolean DEBUG_FLAG = (System.getProperty("debug") != null);

	/** Helper method to print debug messages. */
	private static void debug(String debugMessage) {
		if (DEBUG_FLAG)
			System.err.println(debugMessage);
	}

	/** Domain object. */
	final private Supplier supplier = Supplier.getInstance();

	/** Constructor */
	public SupplierServiceImpl() {
		debug("Loading demo data...");
		supplier.demoData();
	}

	/** Helper method to convert domain product to message product. */
	private Product buildProductFromProduct(pt.tecnico.supplier.domain.Product p) {
		Product.Builder productBuilder = Product.newBuilder();
		productBuilder.setIdentifier(p.getId());
		productBuilder.setDescription(p.getDescription());
		productBuilder.setQuantity(p.getQuantity());

		Money.Builder moneyBuilder = Money.newBuilder();
		moneyBuilder.setCurrencyCode("EUR").setUnits(p.getPrice());
		productBuilder.setPrice(moneyBuilder.build());

		return productBuilder.build();
	}

	@Override
	public void listProducts(ProductsRequest request, StreamObserver<SignedResponse> responseObserver) {
		debug("listProducts called");

		debug("Received request:");
		debug(request.toString());
		debug("in binary hexadecimals:");
		byte[] requestBinary = request.toByteArray();
		debug(String.format("%d bytes%n", requestBinary.length));

		try {
			// build response
			SignedResponse.Builder responseBuilder = SignedResponse.newBuilder();
			ProductsResponse.Builder productsResponseBuilder = responseBuilder.getResponseBuilder();
			productsResponseBuilder.setSupplierIdentifier(supplier.getId());
			for (String pid : supplier.getProductsIDs()) {
				pt.tecnico.supplier.domain.Product p = supplier.getProduct(pid);
				Product product = buildProductFromProduct(p);
				productsResponseBuilder.addProduct(product);
			}

			// get a message digest object using the specified algorithm
			MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

			// calculate the digest and print it out
			byte[] responseBytes = productsResponseBuilder.build().toByteArray();
			messageDigest.update(responseBytes);
			byte[] digest = messageDigest.digest();
			System.out.println("Digest:");
			System.out.println(printHexBinary(digest));

			// get an AES cipher object
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

			// encrypt the plain text using the key
			cipher.init(Cipher.ENCRYPT_MODE, readKey("priv.key"));
			byte[] cipherDigest = cipher.doFinal(digest);

			// build signature
			Signature.Builder signatureBuilder = Signature.newBuilder();
			signatureBuilder.setSignerId("Supplier1");
			ByteString byteString = ByteString.copyFrom(cipherDigest);
			signatureBuilder.setValue(byteString);
			responseBuilder.setSignature(signatureBuilder.build());

			// remove this line to send the response with the original products
			// // ProductsResponse.Builder modifiedProducts = responseBuilder.getResponseBuilder();
			// // modifiedProducts.setSupplierIdentifier("modifiedID");

			// build response
			SignedResponse response = responseBuilder.build();

			debug("Response to send:");
			debug(response.toString());
			debug("in binary hexadecimals:");
			byte[] responseBinary = response.toByteArray();
			debug(printHexBinary(responseBinary));
			debug(String.format("%d bytes%n", responseBinary.length));

			// send single response back
			responseObserver.onNext(response);
			// complete call
			responseObserver.onCompleted();
		} catch (Exception e) {
			e.printStackTrace();
		}

		
	}
}