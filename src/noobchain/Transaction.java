package noobchain;

import java.security.*;
import java.util.ArrayList;

public class Transaction {

    public String transactionId; // This is also the hash of the transaction.
    public PublicKey sender; // Sender's address/public key.
    public PublicKey recipient; // Recipient's address/public key.
    public float value;
    public byte[] signature; // This prevents anyone else from spending funds in the wallet.

    public ArrayList<TransactionInput> inputs = new ArrayList<>();
    public ArrayList<TransactionOutput> outputs = new ArrayList<>();

    private static int sequence = 0; // A rough count of how many transactions have been generated.

    // Constructor:
    public Transaction(PublicKey from, PublicKey to, float value, ArrayList<TransactionInput> inputs) {
        this.sender = from;
        this.recipient = to;
        this.value = value;
        this.inputs = inputs;
    }

    // Calculate the transaction hash (used as the ID).
    private String calculateHash() {
        sequence++; // Increment the sequence to ensure unique hash for each transaction.
        return StringUtil.applySha256(
                StringUtil.getStringFromKey(sender) +
                StringUtil.getStringFromKey(recipient) +
                Float.toString(value) + sequence
        );
    }

    // Sign the transaction data to prevent tampering.
    public void generateSignature(PrivateKey privateKey) {
        String data = StringUtil.getStringFromKey(sender) +
                      StringUtil.getStringFromKey(recipient) +
                      Float.toString(value);
        signature = StringUtil.applyECDSASig(privateKey, data);
    }

    // Verify the signature to ensure the data hasn't been tampered with.
    public boolean verifySignature() {
        String data = StringUtil.getStringFromKey(sender) +
                      StringUtil.getStringFromKey(recipient) +
                      Float.toString(value);
        return StringUtil.verifyECDSASig(sender, data, signature); // Updated: use sender directly
    }
    
    //Returns true if new transaction could be created.
    public boolean processTransaction() {
    	
    	if(verifySignature() == false) {
    		System.out.println("#Transaction Signature failed to verify");
    		return false;
    	}
    	
    	//gather transaction inputs (Make sure they are unspent):
    	for(TransactionInput i : inputs) {
    		i.UTXO = NoobChain.UTXOs.get(i.transactionOutputId);
    	}
    	
    	//check if transaction is valid:
    	if(getInputsValue() < NoobChain.minimumTransaction) {
    		System.out.println("#Transaction Inputs too small: " + getInputsValue());
    		return false;
    	}
    	
    	//generate transaction outputs:
    	float leftOver = getInputsValue() - value; //get value of inputs then the left over change:
    	transactionId = calculateHash();
    	outputs.add(new TransactionOutput( this.recipient, value,transactionId)); //send value to recipient
    	outputs.add(new TransactionOutput( this.sender, leftOver,transactionId)); //send the left over 'change' back to sender
    	
    	//add outputs to Unspent list
    	for(TransactionOutput o : outputs) {
    		NoobChain.UTXOs.put(o.id ,  o);
    	}
    	
    	//remove transaction inputs from UTXO lists as spent:
    	for(TransactionInput i : inputs) {
    		if(i.UTXO == null) continue; //if Transaction can't be found skip it
    		NoobChain.UTXOs.remove(i.UTXO.id);
    	}
    	
    	return true;
    }
    
    //returns sum of inputs(UTXOs) values
    public float getInputsValue() {
    	float total = 0;
    	for(TransactionInput i : inputs) {
    		if(i.UTXO == null) continue; //if Transaction can't be found skip it
    		total += i.UTXO.value;
    	}
    	return total;
    }

	public float getOutputsValue() {
		// TODO Auto-generated method stub
		return 0;
	}
    
}
