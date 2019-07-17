package main;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Iterator;
import java.util.concurrent.ExecutionException;

import org.hyperledger.indy.sdk.IndyException;
import org.hyperledger.indy.sdk.anoncreds.Anoncreds;
import org.hyperledger.indy.sdk.anoncreds.AnoncredsResults.IssuerCreateAndStoreCredentialDefResult;
import org.hyperledger.indy.sdk.anoncreds.AnoncredsResults.IssuerCreateCredentialResult;
import org.hyperledger.indy.sdk.anoncreds.AnoncredsResults.IssuerCreateSchemaResult;
import org.hyperledger.indy.sdk.anoncreds.AnoncredsResults.ProverCreateCredentialRequestResult;
import org.hyperledger.indy.sdk.did.Did;
import org.hyperledger.indy.sdk.did.DidJSONParameters.CreateAndStoreMyDidJSONParameter;
import org.hyperledger.indy.sdk.did.DidResults.CreateAndStoreMyDidResult;
import org.hyperledger.indy.sdk.ledger.Ledger;
import org.hyperledger.indy.sdk.pool.Pool;
import org.hyperledger.indy.sdk.pool.PoolJSONParameters;
import org.hyperledger.indy.sdk.wallet.Wallet;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class ProofReqIssue {

	private static String indyClientPath;

	public static void main(String[] args) throws InterruptedException, ExecutionException, IndyException, IOException {
		String envPath = System.getProperty("user.home");
		indyClientPath = envPath + "/" + ".indy_client";

		File file = new File(indyClientPath);
		if (!file.exists()) {
			file.mkdir();
		}
		System.loadLibrary("indy");

		// write default genesis transactions
		String[] genesisTransactions = getDefaultGenesisTxn("192.168.178.27");
		writeGenesisTransactions(genesisTransactions, "genesis.txn");

		// create and open wallet
		JSONObject walletConfig = new JSONObject();
		JSONObject walletCred = new JSONObject();
		walletConfig.put("id", "defaultWallet");
		walletCred.put("key", "123");
		Wallet.createWallet(walletConfig.toString(), walletCred.toString()).get();
		Wallet myWallet = Wallet.openWallet(walletConfig.toString(), walletCred.toString()).get();

		// create and open pool with protocol version 2
		Pool.setProtocolVersion(2).get();
		PoolJSONParameters.CreatePoolLedgerConfigJSONParameter createPoolLedgerConfigJSONParameter = new PoolJSONParameters.CreatePoolLedgerConfigJSONParameter(
				indyClientPath + "/" + "genesis.txn");
		Pool.createPoolLedgerConfig("defaultPool", createPoolLedgerConfigJSONParameter.toJson()).get();
		Pool myPool = Pool.openPoolLedger("defaultPool", null).get();

		// create steward did from seed
		String seed = "000000000000000000000000Steward1";
		CreateAndStoreMyDidJSONParameter stewardDIDParameter = new CreateAndStoreMyDidJSONParameter(null, seed, null,
				null);
		CreateAndStoreMyDidResult createDidResult = Did.createAndStoreMyDid(myWallet, stewardDIDParameter.toString())
				.get();
		String didSteward = createDidResult.getDid();

		// create trust anchor did and write it to the ledger
		createDidResult = Did.createAndStoreMyDid(myWallet, "{}").get();
		String didTrustAnchor = createDidResult.getDid();
		String keyTrustAnchor = createDidResult.getVerkey();
		String request = Ledger.buildNymRequest(didSteward, didTrustAnchor, keyTrustAnchor, null, "TRUST_ANCHOR").get();
		String response = Ledger.signAndSubmitRequest(myPool, myWallet, didSteward, request).get();

		// trust anchor creates schema and credential definition and writes them to the
		// ledger
		String schemaName = "testschema";
		String version = "1.0";
		JSONArray jsonAttr = new JSONArray();
		jsonAttr.put("licence_number");
		jsonAttr.put("first_name");
		jsonAttr.put("last_name");
		String schemaAttributes = jsonAttr.toString();
		IssuerCreateSchemaResult schemaResult = Anoncreds
				.issuerCreateSchema(didTrustAnchor, schemaName, version, schemaAttributes).get();
		request = Ledger.buildSchemaRequest(didTrustAnchor, schemaResult.getSchemaJson()).get();
		response = Ledger.signAndSubmitRequest(myPool, myWallet, didTrustAnchor, request).get();
		IssuerCreateAndStoreCredentialDefResult credentialResult = Anoncreds.issuerCreateAndStoreCredentialDef(myWallet,
				didTrustAnchor, schemaResult.getSchemaJson(), "myTag", "CL", null).get();
		request = Ledger.buildCredDefRequest(didTrustAnchor, credentialResult.getCredDefJson()).get();
		response = Ledger.signAndSubmitRequest(myPool, myWallet, didTrustAnchor, request).get();

		// trust anchor issues a credential corresponding to the prior created
		// credential definition and issues it to someone
		JSONObject attributesToIssue = new JSONObject();
		attributesToIssue.put("licence_number", "L2ZKT17Q2");
		attributesToIssue.put("first_name", "MyFirstNamePhilipp");
		attributesToIssue.put("last_name", "MyLastNameMorrison");

		JSONObject credentialDataForIndy = encode(attributesToIssue);
		String credentialOffer = Anoncreds.issuerCreateCredentialOffer(myWallet, credentialResult.getCredDefId()).get();

		createDidResult = Did.createAndStoreMyDid(myWallet, "{}").get();
		String didProver = createDidResult.getDid();
		String linkSecret = Anoncreds.proverCreateMasterSecret(myWallet, null).get();

		ProverCreateCredentialRequestResult proverCredReqResult = Anoncreds.proverCreateCredentialReq(myWallet,
				didProver, credentialOffer, credentialResult.getCredDefJson(), linkSecret).get();

		IssuerCreateCredentialResult createCredResult = Anoncreds.issuerCreateCredential(myWallet, credentialOffer,
				proverCredReqResult.getCredentialRequestJson(), credentialDataForIndy.toString(), null, -1).get();

		String credentialReferent = Anoncreds
				.proverStoreCredential(myWallet, null, proverCredReqResult.getCredentialRequestMetadataJson(),
						createCredResult.getCredentialJson(), credentialResult.getCredDefJson(), null)
				.get();

		// The credential has been issued to the prover and he saved it
		// now we want to get a simple proof for licence_number. We want the prover to
		// reveal this attribute.
		// we create a proof request
		JSONObject proofRequest = new JSONObject();
		proofRequest.put("name", "proof_req");
		proofRequest.put("version", "0.1");
		proofRequest.put("nonce", "123432421212");
		JSONObject requested_attributes = new JSONObject();
		JSONObject attribute_info = new JSONObject();
		attribute_info.put("name", "licence_number");
		JSONObject restrictions = new JSONObject();
		restrictions.put("issuer_did", didTrustAnchor); // the restrictin is that the trust anchor issued the credential
		attribute_info.put("restrictions", restrictions);
		requested_attributes.put("attr1_referent", attribute_info);
		proofRequest.put("requested_attributes", requested_attributes);
		proofRequest.put("requested_predicates", new JSONObject());

		// build requested credentials
		String credentials_for_proofRequest = Anoncreds
				.proverGetCredentialsForProofReq(myWallet, proofRequest.toString()).get();

		// System.out.println(credentials_for_proofRequest);

		JSONObject requestedCredentials = new JSONObject();
		JSONObject reqAttributes = new JSONObject();
		String credId = credentialReferent;
		reqAttributes.put("attr1_referent", new JSONObject().put("cred_id", credId).put("revealed", true));
		requestedCredentials.put("self_attested_attributes", new JSONObject());
		requestedCredentials.put("requested_attributes", reqAttributes);
		requestedCredentials.put("requested_predicates", new JSONObject());

		JSONObject schemas = new JSONObject();
		schemas.put(schemaResult.getSchemaId(), new JSONObject(schemaResult.getSchemaJson()));

		JSONObject creds = new JSONObject();
		creds.put(credentialResult.getCredDefId(), new JSONObject(credentialResult.getCredDefJson()));

		String proof = Anoncreds.proverCreateProof(myWallet, proofRequest.toString(), requestedCredentials.toString(),
				linkSecret, schemas.toString(), creds.toString(), new JSONObject().toString()).get();

		System.out.println(proof);
		
		// the proof has been created for the given proof request, now verify it

		JSONObject revocRegDefs = new JSONObject();
		JSONObject revocRegs = new JSONObject();

		Boolean verifyResult = Anoncreds.verifierVerifyProof(proofRequest.toString(), proof, schemas.toString(),
				creds.toString(), revocRegDefs.toString(), revocRegs.toString()).get();
		
		System.out.println("The proof result ist: " + verifyResult);
		
		// now we make a false proof - we replace "licence_number":"1405580844876701323570" in the original proof
		String falseProof1 = proof.replace("\"licence_number\":\"1405580844876701323570\"", "\"licence_number\":\"1111111111111111111170\""); 
		verifyResult = Anoncreds.verifierVerifyProof(proofRequest.toString(), falseProof1, schemas.toString(),
				creds.toString(), revocRegDefs.toString(), revocRegs.toString()).get();
		System.out.println("The falseProof1 result ist: " + verifyResult);
		
		
		// now we make a false proof - we replace "raw":"L2ZKT17Q2" in the original proof
		String falseProof2 = proof.replace("\"raw\":\"L2ZKT17Q2\"", "\"raw\":\"AAAAAAAAA\""); 
		verifyResult = Anoncreds.verifierVerifyProof(proofRequest.toString(), falseProof2, schemas.toString(),
				creds.toString(), revocRegDefs.toString(), revocRegs.toString()).get();
		System.out.println("The falseProof2 result ist: " + verifyResult);
		
		
		myPool.close();
		myWallet.close();

	}

	private static JSONObject encode(JSONObject attributesToIssue) {
		try {
			JSONObject result = new JSONObject();
			Iterator<String> keyIterator = attributesToIssue.keys();
			while (keyIterator.hasNext()) {
				String key = keyIterator.next();
				String rawValue = attributesToIssue.getString(key);
				String encValue = encStringAsInt(rawValue);
				result.put(key, new JSONObject().put("raw", rawValue).put("encoded", encValue));
			}

			return result;
		} catch (JSONException e) {
			return null;
		}
	}

	private static String encStringAsInt(String string) {
		try {
			Integer.parseInt(string);
			return string;
		} catch (Exception e) {
			BigInteger bigInt = new BigInteger(string.getBytes());
			return bigInt.toString();
		}
	}

	private static String[] getDefaultGenesisTxn(String poolIPAddress) {
		String[] s = new String[] { String.format(
				"{\"reqSignature\":{},\"txn\":{\"data\":{\"data\":{\"alias\":\"Node1\",\"blskey\":\"4N8aUNHSgjQVgkpm8nhNEfDf6txHznoYREg9kirmJrkivgL4oSEimFF6nsQ6M41QvhM2Z33nves5vfSn9n1UwNFJBYtWVnHYMATn76vLuL3zU88KyeAYcHfsih3He6UHcXDxcaecHVz6jhCYz1P2UZn2bDVruL5wXpehgBfBaLKm3Ba\",\"blskey_pop\":\"RahHYiCvoNCtPTrVtP7nMC5eTYrsUA8WjXbdhNc8debh1agE9bGiJxWBXYNFbnJXoXhWFMvyqhqhRoq737YQemH5ik9oL7R4NTTCz2LEZhkgLJzB3QRQqJyBNyv7acbdHrAT8nQ9UkLbaVL9NBpnWXBTw4LEMePaSHEw66RzPNdAX1\",\"client_ip\":\"%s\",\"client_port\":9702,\"node_ip\":\"%s\",\"node_port\":9701,\"services\":[\"VALIDATOR\"]},\"dest\":\"Gw6pDLhcBcoQesN72qfotTgFa7cbuqZpkX3Xo6pLhPhv\"},\"metadata\":{\"from\":\"Th7MpTaRZVRYnPiabds81Y\"},\"type\":\"0\"},\"txnMetadata\":{\"seqNo\":1,\"txnId\":\"fea82e10e894419fe2bea7d96296a6d46f50f93f9eeda954ec461b2ed2950b62\"},\"ver\":\"1\"}",
				poolIPAddress, poolIPAddress),
				String.format(
						"{\"reqSignature\":{},\"txn\":{\"data\":{\"data\":{\"alias\":\"Node2\",\"blskey\":\"37rAPpXVoxzKhz7d9gkUe52XuXryuLXoM6P6LbWDB7LSbG62Lsb33sfG7zqS8TK1MXwuCHj1FKNzVpsnafmqLG1vXN88rt38mNFs9TENzm4QHdBzsvCuoBnPH7rpYYDo9DZNJePaDvRvqJKByCabubJz3XXKbEeshzpz4Ma5QYpJqjk\",\"blskey_pop\":\"Qr658mWZ2YC8JXGXwMDQTzuZCWF7NK9EwxphGmcBvCh6ybUuLxbG65nsX4JvD4SPNtkJ2w9ug1yLTj6fgmuDg41TgECXjLCij3RMsV8CwewBVgVN67wsA45DFWvqvLtu4rjNnE9JbdFTc1Z4WCPA3Xan44K1HoHAq9EVeaRYs8zoF5\",\"client_ip\":\"%s\",\"client_port\":9704,\"node_ip\":\"%s\",\"node_port\":9703,\"services\":[\"VALIDATOR\"]},\"dest\":\"8ECVSk179mjsjKRLWiQtssMLgp6EPhWXtaYyStWPSGAb\"},\"metadata\":{\"from\":\"EbP4aYNeTHL6q385GuVpRV\"},\"type\":\"0\"},\"txnMetadata\":{\"seqNo\":2,\"txnId\":\"1ac8aece2a18ced660fef8694b61aac3af08ba875ce3026a160acbc3a3af35fc\"},\"ver\":\"1\"}\n",
						poolIPAddress, poolIPAddress),
				String.format(
						"{\"reqSignature\":{},\"txn\":{\"data\":{\"data\":{\"alias\":\"Node3\",\"blskey\":\"3WFpdbg7C5cnLYZwFZevJqhubkFALBfCBBok15GdrKMUhUjGsk3jV6QKj6MZgEubF7oqCafxNdkm7eswgA4sdKTRc82tLGzZBd6vNqU8dupzup6uYUf32KTHTPQbuUM8Yk4QFXjEf2Usu2TJcNkdgpyeUSX42u5LqdDDpNSWUK5deC5\",\"blskey_pop\":\"QwDeb2CkNSx6r8QC8vGQK3GRv7Yndn84TGNijX8YXHPiagXajyfTjoR87rXUu4G4QLk2cF8NNyqWiYMus1623dELWwx57rLCFqGh7N4ZRbGDRP4fnVcaKg1BcUxQ866Ven4gw8y4N56S5HzxXNBZtLYmhGHvDtk6PFkFwCvxYrNYjh\",\"client_ip\":\"%s\",\"client_port\":9706,\"node_ip\":\"%s\",\"node_port\":9705,\"services\":[\"VALIDATOR\"]},\"dest\":\"DKVxG2fXXTU8yT5N7hGEbXB3dfdAnYv1JczDUHpmDxya\"},\"metadata\":{\"from\":\"4cU41vWW82ArfxJxHkzXPG\"},\"type\":\"0\"},\"txnMetadata\":{\"seqNo\":3,\"txnId\":\"7e9f355dffa78ed24668f0e0e369fd8c224076571c51e2ea8be5f26479edebe4\"},\"ver\":\"1\"}\n",
						poolIPAddress, poolIPAddress),
				String.format(
						"{\"reqSignature\":{},\"txn\":{\"data\":{\"data\":{\"alias\":\"Node4\",\"blskey\":\"2zN3bHM1m4rLz54MJHYSwvqzPchYp8jkHswveCLAEJVcX6Mm1wHQD1SkPYMzUDTZvWvhuE6VNAkK3KxVeEmsanSmvjVkReDeBEMxeDaayjcZjFGPydyey1qxBHmTvAnBKoPydvuTAqx5f7YNNRAdeLmUi99gERUU7TD8KfAa6MpQ9bw\",\"blskey_pop\":\"RPLagxaR5xdimFzwmzYnz4ZhWtYQEj8iR5ZU53T2gitPCyCHQneUn2Huc4oeLd2B2HzkGnjAff4hWTJT6C7qHYB1Mv2wU5iHHGFWkhnTX9WsEAbunJCV2qcaXScKj4tTfvdDKfLiVuU2av6hbsMztirRze7LvYBkRHV3tGwyCptsrP\",\"client_ip\":\"%s\",\"client_port\":9708,\"node_ip\":\"%s\",\"node_port\":9707,\"services\":[\"VALIDATOR\"]},\"dest\":\"4PS3EDQ3dW1tci1Bp6543CfuuebjFrg36kLAUcskGfaA\"},\"metadata\":{\"from\":\"TWwCRQRZ2ZHMJFn9TzLp7W\"},\"type\":\"0\"},\"txnMetadata\":{\"seqNo\":4,\"txnId\":\"aa5e817d7cc626170eca175822029339a444eb0ee8f0bd20d3b0b76e566fb008\"},\"ver\":\"1\"}",
						poolIPAddress, poolIPAddress) };
		return s;
	}

	private static void writeGenesisTransactions(String[] genesisContent, String genesisFileName) throws IOException {
		File genesisFile = new File(indyClientPath + "/" + genesisFileName);
		FileWriter fw = new FileWriter(genesisFile);
		for (String s : genesisContent) {
			fw.write(s);
			fw.write("\n");
		}
		fw.flush();
		fw.close();

	}

}
