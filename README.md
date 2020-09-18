# BDOIndia-GSPEncDecUtility - An encryption decryption utility tool
EncriptionUtility.java should be used to encrypt and decrypt the data as required.
For GSP we will have two public keys 
i. One is bdo public keys( which is required to encrypt the bdo credential to hit the bdo auth api)
ii. NIC public key ( require to encrypt for NIC authentication api hit)
    
The function names are self explanatory:
i.  encryptWithBDOPubKey(..) -> required for BDO authentication
ii. getAppKey() -> To get an random appkey
iii. encryptPasswordWithPubKey -> for NIC authentication
iv. encryptAppKeyWithPubKey(..) -> for App key encryption
v. decryptSEK(..) -> To decrypt the SEK
vi. encryptPayload(..) -> To encrypt the payload to upload
vii. decryptResponseData(..) -> To decrypt response data
