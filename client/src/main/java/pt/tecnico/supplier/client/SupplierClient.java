package pt.tecnico.supplier.client;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import pt.tecnico.supplier.grpc.ProductsRequest;
import pt.tecnico.supplier.grpc.SupplierGrpc;
import javax.crypto.spec.SecretKeySpec;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import pt.tecnico.supplier.grpc.SignedResponse;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;

import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class SupplierClient {

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

	private static byte[] readFile(String path) throws FileNotFoundException, IOException {
		InputStream fis = Thread.currentThread().getContextClassLoader().getResourceAsStream(path);
		byte[] content = new byte[fis.available()];
		fis.read(content);
		fis.close();
		return content;
	}

	public static PublicKey readKey(String resourcePathName) throws Exception {
		System.out.println("Reading public key from file " + resourcePathName + " ...");
		byte[] pubEncoded = readFile(resourcePathName);

		X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubEncoded);
		KeyFactory keyFacPub = KeyFactory.getInstance("RSA");
		PublicKey pub = keyFacPub.generatePublic(pubSpec);
		return pub;
	}

	public static void main(String[] args) throws Exception {
		System.out.println(SupplierClient.class.getSimpleName() + " starting ...");

		// Receive and print arguments.
		System.out.printf("Received %d arguments%n", args.length);
		for (int i = 0; i < args.length; i++) {
			System.out.printf("arg[%d] = %s%n", i, args[i]);
		}

		// Check arguments.
		if (args.length < 2) {
			System.err.println("Argument(s) missing!");
			System.err.printf("Usage: java %s host port%n", SupplierClient.class.getName());
			return;
		}

		final String host = args[0];
		final int port = Integer.parseInt(args[1]);
		final String target = host + ":" + port;

		// Channel is the abstraction to connect to a service end-point.
		final ManagedChannel channel = ManagedChannelBuilder.forTarget(target).usePlaintext().build();

		// Create a blocking stub for making synchronous remote calls.
		SupplierGrpc.SupplierBlockingStub stub = SupplierGrpc.newBlockingStub(channel);

		// Prepare request.
		ProductsRequest request = ProductsRequest.newBuilder().build();
		System.out.println("Request to send:");
		System.out.println(request.toString());
		debug("in binary hexadecimals:");
		byte[] requestBinary = request.toByteArray();
		debug(printHexBinary(requestBinary));
		debug(String.format("%d bytes%n", requestBinary.length));

		// Make the call using the stub.
		System.out.println("Remote call...");
		SignedResponse response = stub.listProducts(request);
		
		// get an AES cipher object
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		// decrypt the text
		cipher.init(Cipher.DECRYPT_MODE, readKey("pub.key"));
		byte[] decipheredDigest = cipher.doFinal(response.getSignature().getValue().toByteArray());
		
		// get a message digest object using the specified algorithm
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

		// calculate the digest and print it out
		byte[] responseBytes = response.getResponse().toByteArray();
		messageDigest.update(responseBytes);
		byte[] digest = messageDigest.digest();
		System.out.println("Digest:");
		System.out.println(printHexBinary(digest));

		if (Arrays.equals(digest, decipheredDigest)) {
			System.out.println("Signature is valid! Message accepted! :)");
		} else {
			System.out.println("Signature is invalid! Message rejected! :(");
		}

		// Print response.
		System.out.println("Received response:");
		System.out.println(response.toString());
		debug("in binary hexadecimals:");
		byte[] responseBinary = response.toByteArray();
		debug(printHexBinary(responseBinary));
		debug(String.format("%d bytes%n", responseBinary.length));

		// A Channel should be shutdown before stopping the process.
		channel.shutdownNow();
	}

}
