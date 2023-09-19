package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	//"strings"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username []byte
	PWHash   []byte
	UserId   userlib.UUID

	SignKey    userlib.PrivateKeyType
	RSAPrivate userlib.PrivateKeyType

	//InviteDirectory map[string]userlib.UUID
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

/*Self-Defined Structs*/

type DataStoreEntry struct {
	EncrpytedCipherText []byte
	HMACSignature       []byte
}

type FileRecord struct {
	Owned    bool
	FileID   userlib.UUID
	InviteID userlib.UUID
}

type File struct {
	FirstBlock userlib.UUID
	LastBlock  userlib.UUID
}

type Block struct {
	//PrevBlock userlib.UUID
	NextBlock userlib.UUID
	Data      []byte
}

type Invite struct {
	FileID        userlib.UUID
	CipherKey     []byte
	CipherKeySig  []byte
	CipherHMAC    []byte
	CipherHMACSig []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {

	if len(username) == 0 {
		return nil, errors.New("InitUser: Username should not be empty")
	}
	var userdata User
	hexEncoded := hex.EncodeToString([]byte(username))
	_, ok := userlib.KeystoreGet(hexEncoded + "rsa")
	if ok {
		return nil, errors.New("InitUser: User already exist")
	}
	_, ok = userlib.KeystoreGet(hexEncoded + "verify")
	if ok {
		return nil, errors.New("InitUser: User already exist")
	}
	hexDecoded, err := hex.DecodeString(hexEncoded)
	hexDecodedPassword, err := hex.DecodeString(hex.EncodeToString([]byte(password)))

	if err != nil {
		panic(err)
	}
	userdata.Username = hexDecoded
	userdata.PWHash = userlib.Argon2Key(hexDecodedPassword, hexDecoded, 64)
	if err != nil {
		return nil, errors.New("InitUser: Failed to Encode Purpose UserId to bytes")
	}
	userid, err := userlib.HashKDF(userdata.PWHash[:16],
		[]byte("userid"))
	if err != nil {
		return nil, errors.New("InitUser: Failed to create UserId")
	}

	/*Check if Username Already Exist*/
	id, err := uuid.FromBytes(userid[:16])

	userdata.UserId = id
	encryptionKeyUserdata, err := userlib.HashKDF(userdata.PWHash[16:32], []byte("encryptionKeyUserdata"))
	if err != nil {
		return nil, errors.New("InitUser: HashKDF Failed -- encryptionKeyUserdata")
	}

	hmacUserdata, err := userlib.HashKDF(userdata.PWHash[32:48], []byte("hmac"))
	if err != nil {
		return nil, errors.New("InitUser: HashKDF Failed -- hmacUserdata")
	}

	/*Key Generations*/
	//Signature Generation
	signKey, verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, errors.New("InitUser: Failed to generate signatures")
	}
	userdata.SignKey = signKey
	//RSA Key
	rsaPublic, rsaPrivate, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, errors.New("InitUser: Failed to generate rsa keys")
	}

	//userdata.RSAPublic = rsaPublic
	userdata.RSAPrivate = rsaPrivate

	//Store Public Keys
	userlib.KeystoreSet(hexEncoded+"rsa", rsaPublic)
	userlib.KeystoreSet(hexEncoded+"verify", verifyKey)
	/*Storing userdata to Datastore*/
	//Store user data
	marshal1, err := json.Marshal(userdata)
	if err != nil {
		return nil, errors.New("InitUser: Error marshalling user data")
	}
	err = StoreToDataStore(marshal1, encryptionKeyUserdata[:16], hmacUserdata[:16], id)
	if err != nil {
		return nil, errors.New("InitUser: Failed to Store Userdata to Datastore")
	}
	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {

	hexEncoded := hex.EncodeToString([]byte(username))
	_, ok := userlib.KeystoreGet(hexEncoded + "rsa")
	if !ok {
		return nil, errors.New("GetUser: User does not exist")
	}
	_, ok = userlib.KeystoreGet(hexEncoded + "verify")
	if !ok {
		return nil, errors.New("GetUser: User does not exist")
	}
	hexDecoded, err := hex.DecodeString(hexEncoded)
	hexDecodedPassword, err := hex.DecodeString(hex.EncodeToString([]byte(password)))

	verifyPWHash := userlib.Argon2Key(hexDecodedPassword, hexDecoded, 64)
	verifyUserid, err := userlib.HashKDF(verifyPWHash[:16], []byte("userid"))
	if err != nil {
		return nil, errors.New("GetUser: Failed to Generate UserID")
	}
	verifyId, err := uuid.FromBytes(verifyUserid[:16])
	if err != nil {
		return nil, errors.New("GetUser: Failed to Parse to UUID")
	}
	verifyEncryptionKey, err := userlib.HashKDF(verifyPWHash[16:32], []byte("encryptionKeyUserdata"))
	if err != nil {
		return nil, errors.New("GetUser: Failed to Generate Encryption Key")
	}
	verifyHmac, err := userlib.HashKDF(verifyPWHash[32:48], []byte("hmac"))
	if err != nil {
		return nil, errors.New("GetUser: Failed to Generate HMAC")
	}

	marshal2, ok := userlib.DatastoreGet(verifyId)
	if !ok {
		return nil, errors.New("GetUser: Error getting user data")
	}
	//Decrypt user data
	userdataBytes, err := DataStoreToMarshall1(marshal2, verifyEncryptionKey[:16], verifyHmac[:16])
	var userdata User
	userdataptr = &userdata
	err = json.Unmarshal(userdataBytes, userdataptr)
	if err != nil {
		return nil, errors.New("GetUser: Error unmarshalling encrypted user data")
	}
	if bytes.Compare(userdata.Username, hexDecoded) != 0 {
		return nil, errors.New("GetUser: Error username mismatch")
	}
	if !userlib.HMACEqual(userdata.PWHash, verifyPWHash) {
		return nil, errors.New("GetUser: Error password mismatch")
	}
	if userdata.UserId != verifyId {
		return nil, errors.New("GetUser: Error UserId mismatch")
	}
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	filename = hex.EncodeToString([]byte(filename))

	storageKey, encryptionKey, hmacKey, err := userdata.generateFileKey(filename)
	if err != nil {
		return errors.New("StoreFile: Failed to generate file key")
	}

	//Generate File Structure
	var fileRecord FileRecord
	var fileStruct File

	fileRecordMarshal2, ok := userlib.DatastoreGet(storageKey)

	/*Not ok meaning file does not exist*/
	if !ok {
		fileRecord.FileID = uuid.New()
		fileRecord.Owned = true
		//fileRecord.ownername = userdata.Username
		fileRecord.InviteID = uuid.Nil
		//shareListID, err := userdata.getShareListID(filename)
		if err != nil {
			return errors.New("StoreFile: Failed to get ShareListID")
		}

	}
	if ok {
		result, err := DataStoreToMarshall1(fileRecordMarshal2, encryptionKey[:16], hmacKey[:16])
		if err != nil {
			return errors.New("StoreFile: Failed to Unmarshal Content")
		}
		json.Unmarshal(result, &fileRecord)
	}

	idToStore := fileRecord.FileID
	if !fileRecord.Owned {
		if idToStore != uuid.Nil {
			return errors.New("StoreFile: Not owned file should not have fileRecord.FileID")
		}

		//Get inviteID
		inviteID := fileRecord.InviteID
		if inviteID == uuid.Nil {
			return errors.New("StoreFile: Not owned file should have inviteID")
		}

		marshal2, ok := userlib.DatastoreGet(inviteID)
		if !ok {
			return errors.New("StoreFile: Unable to get invite")
		}

		var rawDataStoreInvite DataStoreEntry
		err = json.Unmarshal(marshal2, &rawDataStoreInvite)
		if err != nil {
			return errors.New("decryptInvite: Unable to unmarshal Raw DataStore Invite")
		}

		content, _ := rawDataStoreInvite.EncrpytedCipherText, rawDataStoreInvite.HMACSignature

		marshal1, err := pkeDec(userdata.RSAPrivate, content)
		if err != nil {
			return errors.New("decryptInvite: Unable to decrypt cipherText")
		}
		var newInvite Invite

		json.Unmarshal(marshal1, &newInvite)
		if err != nil {
			return err
		}

		idToStore, encryptionKey, hmacKey, err = newInvite.decryptKeysFromInvite(userdata)
	}

	err = fileStruct.StoreToFileStruct(content, encryptionKey, hmacKey)
	if err != nil {
		return errors.New("StoreFile: Failed to Store Content to FileStruct")
	}

	//Store FileStruct to fileRecord.FileID
	marshal1, err := json.Marshal(fileStruct)
	if err != nil {
		return errors.New("StoreFile: Error marshalling fileStruct")
	}

	err = StoreToDataStore(marshal1, encryptionKey[:16], hmacKey[:16], idToStore)
	if err != nil {
		return errors.New("StoreFile: Failed to Store FileStruct to Datastore")
	}
	//Store FileRecord to storageKey
	marshal1, err = json.Marshal(fileRecord)
	if err != nil {
		return errors.New("StoreFile: Error marshalling fileRecord")
	}
	storageKey, encryptionKey, hmacKey, err = userdata.generateFileKey(filename)
	err = StoreToDataStore(marshal1, encryptionKey[:16], hmacKey[:16], storageKey)
	if err != nil {
		return err
	}

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	filename = hex.EncodeToString([]byte(filename))
	var fileRecord FileRecord
	var fileStruct File
	var contentBlock, empty Block
	storageKey, encryptionKey, hmacKey, err := userdata.generateFileKey(filename)
	if err != nil {
		return err
	}

	/*Get File Record*/
	marshal1, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return errors.New("AppendToFile: File not found")
	}
	result, err := DataStoreToMarshall1(marshal1, encryptionKey[:16], hmacKey[:16])
	if err != nil {
		return errors.New("AppendToFile: Failed to Unmarshal Content")
	}
	json.Unmarshal(result, &fileRecord)

	fileID := fileRecord.FileID

	if !fileRecord.Owned {
		// update encryptionKey, hmacKey
		// update fileID
		if fileRecord.InviteID == uuid.Nil {
			return errors.New("AppendToFile: Not Owned, no inviteID")
		}
		var myInvite Invite
		var dataStoreEntry DataStoreEntry

		dataJSON, ok := userlib.DatastoreGet(fileRecord.InviteID)
		if !ok {
			return errors.New("AppendToFile: Not Owner, Fail to find Invite")
		}

		json.Unmarshal(dataJSON, &dataStoreEntry)

		marshal1, err := pkeDec(userdata.RSAPrivate, dataStoreEntry.EncrpytedCipherText)
		if err != nil {
			return errors.New("AppendToFile: Not Owner, Failed to Verify Signature")
		}
		json.Unmarshal(marshal1, &myInvite)

		fileID, encryptionKey, hmacKey, err = myInvite.decryptKeysFromInvite(userdata)
	}

	/*Get File Struct*/
	marshal1, ok = userlib.DatastoreGet(fileID)
	if !ok {
		return errors.New("AppendToFile: File not found")
	}
	result, err = DataStoreToMarshall1(marshal1, encryptionKey[:16], hmacKey[:16])
	if err != nil {
		return errors.New("AppendToFile: Failed to Unmarshal Content")
	}
	json.Unmarshal(result, &fileStruct)

	/*Get Last Block*/
	var lastBlockUUID uuid.UUID
	lastBlockUUID = fileStruct.LastBlock
	contentBlock.Data = content
	fileStruct.LastBlock = uuid.New()
	contentBlock.NextBlock = fileStruct.LastBlock

	/*Store Content Block*/
	marshal1, err = json.Marshal(contentBlock)
	if err != nil {
		return err
	}
	err = StoreToDataStore(marshal1, encryptionKey[:16], hmacKey[:16], lastBlockUUID)
	if err != nil {
		return err
	}

	/*Store Empty Block*/
	marshal1, err = json.Marshal(empty)
	if err != nil {
		return err
	}
	err = StoreToDataStore(marshal1, encryptionKey[:16], hmacKey[:16], fileStruct.LastBlock)
	if err != nil {
		return err
	}

	/*Store File Struct*/
	marshal1, err = json.Marshal(fileStruct)
	if err != nil {
		return err
	}
	err = StoreToDataStore(marshal1, encryptionKey[:16], hmacKey[:16], fileID)
	if err != nil {
		return err
	}

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	filename = hex.EncodeToString([]byte(filename))
	storageKey, encryptionKey, hmacKey, err := userdata.generateFileKey(filename)
	if err != nil {
		return nil, err
	}
	var fileRecord FileRecord
	var fileStruct File
	var contentBlock Block

	var lastBlockUUID, currBlockUUID uuid.UUID

	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New("LoadFile: File Record not found")
	}
	result, err := DataStoreToMarshall1(dataJSON, encryptionKey[:16], hmacKey[:16])
	if err != nil {
		return nil, errors.New("LoadFile: Failed to Unmarshal Content")
	}

	json.Unmarshal(result, &fileRecord)
	fileID := fileRecord.FileID

	if !fileRecord.Owned {
		if fileRecord.InviteID == uuid.Nil {
			return nil, errors.New("LoadFile: Not Owned, no inviteID")
		}
		var myInvite Invite
		var dataStoreEntry DataStoreEntry

		dataJSON, ok := userlib.DatastoreGet(fileRecord.InviteID)
		if !ok {
			return nil, errors.New("LoadFile: Not Owner, Failed to Verify Signature")
		}

		json.Unmarshal(dataJSON, &dataStoreEntry)

		marshal1, err := pkeDec(userdata.RSAPrivate, dataStoreEntry.EncrpytedCipherText) //TODO: NOT PROPERLY PKE DEC
		if err != nil {
			return nil, errors.New("CreateInvite: Not Owner, Failed to Verify Signature")
		}
		json.Unmarshal(marshal1, &myInvite)

		fileID, encryptionKey, hmacKey, err = myInvite.decryptKeysFromInvite(userdata)
	}

	dataJSON, ok = userlib.DatastoreGet(fileID)
	if !ok {
		return nil, errors.New("LoadFile: File not found")
	}
	result, err = DataStoreToMarshall1(dataJSON, encryptionKey[:16], hmacKey[:16])
	if err != nil {
		return nil, errors.New("LoadFile: Failed to Unmarshal Content")
	}
	json.Unmarshal(result, &fileStruct)

	currBlockUUID = fileStruct.FirstBlock
	lastBlockUUID = fileStruct.LastBlock

	for currBlockUUID != lastBlockUUID {
		dataJSON, ok = userlib.DatastoreGet(currBlockUUID)
		if !ok {
			return nil, errors.New("LoadFile: File not found")
		}
		result, err = DataStoreToMarshall1(dataJSON, encryptionKey[:16], hmacKey[:16])
		if err != nil {
			return nil, errors.New("LoadFile: Failed to Unmarshal Content")
		}
		json.Unmarshal(result, &contentBlock)
		content = append(content, contentBlock.Data...)
		currBlockUUID = contentBlock.NextBlock
	}

	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	filename = hex.EncodeToString([]byte(filename))
	recipientUsername = hex.EncodeToString([]byte(recipientUsername))
	random, err := hex.DecodeString(recipientUsername)

	if bytes.Equal(userdata.Username, random) {
		return uuid.Nil, errors.New("CreateInvitation: Cannot Invite Self")
	}
	storageKey, encryptionKey, hmacKey, err := userdata.generateFileKey(filename)
	if err != nil {
		return uuid.Nil, err
	}

	var fileRecord FileRecord
	var newInvite Invite

	rsaKey, ok := userlib.KeystoreGet(recipientUsername + "rsa")
	if !ok {
		return uuid.Nil, errors.New("CreateInvitation: RSA Key not found")
	}

	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return uuid.Nil, errors.New("CreateInvitation: File Record not found")
	}

	result, err := DataStoreToMarshall1(dataJSON, encryptionKey[:16], hmacKey[:16])
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: Failed to Unmarshal Content")
	}

	newInviteID := uuid.New()

	json.Unmarshal(result, &fileRecord)
	currInviteID := fileRecord.InviteID
	shareListID, err := userdata.getShareListID(filename)
	var sharingList map[string]uuid.UUID
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: ShareList not found")
	}
	if fileRecord.Owned {
		if currInviteID != uuid.Nil {
			return uuid.Nil, errors.New("CreateInvitation: Owned but have an InviteID")
		}
		marshal2, ok := userlib.DatastoreGet(shareListID)
		if !ok {
			sharingList = make(map[string]uuid.UUID)
		}

		if ok {
			marshal1, err := DataStoreToMarshall1(marshal2, encryptionKey[:16], hmacKey[:16])
			if err != nil {
				return uuid.Nil, errors.New("CreateInvitation: Failed to Unmarshal Content")
			}
			json.Unmarshal(marshal1, &sharingList)
		}
		_, found := sharingList[recipientUsername]
		if found {
			return uuid.Nil, errors.New("CreateInvitation: Invitation already exists")
		}
		sharingList[recipientUsername] = newInviteID
		newInvite.CipherKey, newInvite.CipherKeySig, newInvite.CipherHMAC, newInvite.CipherHMACSig, err =
			userdata.HybridEncryption(encryptionKey, hmacKey, recipientUsername)
		if err != nil {
			return uuid.Nil, errors.New("CreateInvitation: Failed to Encrypt Content")
		}
		if fileRecord.FileID == uuid.Nil {
			return uuid.Nil, errors.New("CreateInvitation: Owned but no fileID")
		}
		newInvite.FileID = fileRecord.FileID
	}

	if !fileRecord.Owned {
		if fileRecord.InviteID == uuid.Nil {
			return uuid.Nil, errors.New("CreateInvitation: Not Owned, no inviteID")
		}

		if fileRecord.FileID != uuid.Nil {
			return uuid.Nil, errors.New("CreateInvitation: Not Owned but fileID exists")
		}
		marshal2, ok := userlib.DatastoreGet(currInviteID)
		if !ok {
			return uuid.Nil, errors.New("CreateInvitation: InviteID not found")
		}
		marshal2, ok = userlib.DatastoreGet(shareListID)

		if !ok {
			sharingList = make(map[string]uuid.UUID)
		}
		if ok {
			marshal1, err := DataStoreToMarshall1(marshal2, encryptionKey[:16], hmacKey[:16])
			if err != nil {
				return uuid.Nil, errors.New("CreateInvitation: Failed to Unmarshal Content")
			}
			json.Unmarshal(marshal1, &sharingList)
		}

		_, found := sharingList[recipientUsername]
		if found {
			return uuid.Nil, errors.New("CreateInvitation: Invitation already exists")
		}
		sharingList[recipientUsername] = newInviteID
		currInvite, err := userdata.decryptInviteNoVerify(fileRecord.InviteID)
		fileID, encryptionKey, hmacKey, err := currInvite.decryptKeysFromInvite(userdata)
		userlib.DebugMsg("CreateInvitation, Not Owned: myUsername: %s, myInviteID: %s, myFileID: %s, "+
			"myInviteFileID: %s",
			userdata.Username, fileRecord.InviteID, fileRecord.FileID, fileID)
		newInvite.CipherKey, newInvite.CipherKeySig, newInvite.CipherHMAC, newInvite.CipherHMACSig, err =
			userdata.HybridEncryption(encryptionKey, hmacKey, recipientUsername)
		newInvite.FileID = fileID
		if err != nil {
			return uuid.Nil, err
		}

	}

	marshal1, err := json.Marshal(newInvite)
	if err != nil {
		return uuid.Nil, err
	}

	cipheredInvite, err := pkeEnc(rsaKey, marshal1)
	if err != nil {
		return uuid.Nil, err
	}
	sig, err := userlib.DSSign(userdata.SignKey, cipheredInvite)
	if err != nil {
		return uuid.Nil, err
	}

	inviteFinal := DataStoreEntry{
		EncrpytedCipherText: cipheredInvite,
		HMACSignature:       sig,
	}

	marshal2, err := json.Marshal(inviteFinal)
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: Failed to Marshal InviteFinal")
	}
	userlib.DatastoreSet(newInviteID, marshal2)
	storageKey, encryptionKey, hmacKey, err = userdata.generateFileKey(filename)
	sharingListID, err := userdata.getShareListID(filename)
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: ShareList not found")
	}

	marshal1, err = json.Marshal(sharingList)
	if err != nil {
		return uuid.Nil, errors.New("CreateInvitation: Failed to Marshal SharingList")
	}
	StoreToDataStore(marshal1, encryptionKey[:16], hmacKey[:16], sharingListID)

	err = storeFileRecord(fileRecord, storageKey, encryptionKey, hmacKey)
	if err != nil {
		return uuid.Nil, err
	}
	return newInviteID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {

	senderUsername = hex.EncodeToString([]byte(senderUsername))
	filename = hex.EncodeToString([]byte(filename))

	storageKey, encryptionKey, hmacKey, err := userdata.generateFileKey(filename)
	if err != nil {
		return err
	}
	_, ok := userlib.DatastoreGet(storageKey)
	if ok {
		return errors.New("AcceptInvitation: File Record already exists")
	}

	marshal2, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("decryptInvite: Unable to get invite")
	}

	var rawDataStoreInvite DataStoreEntry
	err = json.Unmarshal(marshal2, &rawDataStoreInvite)
	if err != nil {
		return errors.New("decryptInvite: Unable to unmarshal Raw DataStore Invite")
	}

	content, sig := rawDataStoreInvite.EncrpytedCipherText, rawDataStoreInvite.HMACSignature

	verifyKey, ok := userlib.KeystoreGet(senderUsername + "verify")
	if !ok {
		return errors.New("decryptInvite: Unable to get verify key")
	}

	err = userlib.DSVerify(verifyKey, content, sig)
	if err != nil {
		return errors.New("decryptInvite: Unable to verify cipherText")
	}

	marshal1, err := pkeDec(userdata.RSAPrivate, content)
	if err != nil {
		return errors.New("decryptInvite: Unable to decrypt cipherText")
	}
	var newInvite Invite

	json.Unmarshal(marshal1, &newInvite)
	if err != nil {
		return err
	}

	var fileRecord FileRecord
	encryptionKey, hmacKey, err = userdata.HybridDecryptionNoVerify(newInvite.CipherKey, newInvite.CipherHMAC)
	fileRecord.InviteID = invitationPtr
	fileRecord.Owned = false
	fileRecord.FileID = uuid.Nil

	storageKey, encryptionKey, hmacKey, err = userdata.generateFileKey(filename)

	userlib.DebugMsg("AcceptInvitation: myUsername: %s, fileRecord.fileID: %s, sender: %s, invite.FileID:%s, "+
		"fileRecord.InviteID: %s", userdata.Username,
		fileRecord.FileID, senderUsername, newInvite.FileID, fileRecord.InviteID)
	err = storeFileRecord(fileRecord, storageKey, encryptionKey, hmacKey)
	if err != nil {
		return err
	}

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {

	filename = hex.EncodeToString([]byte(filename))
	recipientUsername = hex.EncodeToString([]byte(recipientUsername))

	storageKey, encryptionKey, hmacKey, err := userdata.generateFileKey(filename)
	if err != nil {
		return err
	}

	marshal2, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return errors.New("RevokeAccess: File Record does not exist")
	}
	marshal1, err := DataStoreToMarshall1(marshal2, encryptionKey[:16], hmacKey[:16])
	var fileRecord FileRecord
	var fileStruct File

	err = json.Unmarshal(marshal1, &fileRecord)

	if !fileRecord.Owned {
		return errors.New("RevokeAccess: Not user calling Revoke Access, Undefined Behavior")
	}
	if err != nil {
		return errors.New("RevokeAccess: Unable to unmarshal File Record")
	}
	oldFileID := fileRecord.FileID
	newfileID := uuid.New()
	content, err := userdata.loadAndDelete(oldFileID, encryptionKey[:16], hmacKey[:16])
	err = fileStruct.StoreToFileStruct(content, encryptionKey[:16], hmacKey[:16])
	if err != nil {
		return errors.New("RevokeAccess: StoreFile: Failed to Store Content to FileStruct")
	}

	marshal1, err = json.Marshal(fileStruct)
	if err != nil {
		return errors.New("StoreFile: Error marshalling fileStruct")
	}

	err = StoreToDataStore(marshal1, encryptionKey[:16], hmacKey[:16], newfileID)
	if err != nil {
		return errors.New("StoreFile: Failed to Store FileStruct to Datastore")
	}
	userlib.DatastoreDelete(oldFileID)

	var sharingList map[string]uuid.UUID
	fileRecord.FileID = newfileID
	shareListID, err := userdata.getShareListID(filename)
	marshal2, ok = userlib.DatastoreGet(shareListID)
	if !ok {
		return errors.New("RevokeAccess: Unable to get ShareList")
	}
	marshal1, err = DataStoreToMarshall1(marshal2, encryptionKey[:16], hmacKey[:16])
	//userlib.DebugMsg("RevokeAccess: ShareList, Marshal 1: %v", string(marshal1))
	if !ok {
		return errors.New("RevokeAccess: ShareList does not exist")
	}

	json.Unmarshal(marshal1, &sharingList)
	revokingInviteID, found := sharingList[recipientUsername]
	if !found {
		return errors.New("RevokeAccess: Invitation does not Exist")
	}
	_, ok = userlib.DatastoreGet(revokingInviteID)
	if !ok {
		return errors.New("RevokeAccess: Unable to get invite")
	}
	userlib.DatastoreDelete(revokingInviteID)

	delete(sharingList, recipientUsername)

	for recipientUsername, tempInviteID := range sharingList {
		var newInvite Invite
		newInvite.CipherKey, newInvite.CipherKeySig, newInvite.CipherHMAC, newInvite.CipherHMACSig, err =
			userdata.HybridEncryption(encryptionKey, hmacKey, recipientUsername)
		newInvite.FileID = newfileID
		marshal1, err := json.Marshal(newInvite)
		if err != nil {
			return err
		}
		rsaKey, ok := userlib.KeystoreGet(recipientUsername + "rsa")
		if !ok {
			return errors.New("RevokeAccess: Unable to get RSA Key")
		}

		cipheredInvite, err := pkeEnc(rsaKey, marshal1)
		if err != nil {
			return err
		}
		sig, err := userlib.DSSign(userdata.SignKey, cipheredInvite)
		if err != nil {
			return err
		}

		inviteFinal := DataStoreEntry{
			EncrpytedCipherText: cipheredInvite,
			HMACSignature:       sig,
		}

		marshal2, err := json.Marshal(inviteFinal)
		if err != nil {
			return errors.New("RevokeAccess: Failed to Marshal InviteFinal")
		}
		userlib.DatastoreSet(tempInviteID, marshal2)

	}

	marshal1, err = json.Marshal(fileRecord)
	if err != nil {
		return errors.New("RevokeAccess: Unable to Marshal File Record")
	}
	storageKey, encryptionKey, hmacKey, err = userdata.generateFileKey(filename)
	if err != nil {
		return err
	}

	err = StoreToDataStore(marshal1, encryptionKey[:16], hmacKey[:16], storageKey)
	if err != nil {
		return err
	}

	marshal1, err = json.Marshal(sharingList)
	if err != nil {
		return errors.New("StoreFile: Error marshalling sharingList")
	}

	err = StoreToDataStore(marshal1, encryptionKey[:16], hmacKey[:16], shareListID)
	if err != nil {
		return errors.New("StoreFile: Failed to Store sharingList to Datastore")
	}

	userlib.DatastoreDelete(oldFileID)

	return nil
}

/*Helper Functions*/

func DataStoreToMarshall1(marshal2 []byte, EncryptionKey []byte, HMACKey []byte) (result []byte, err error) {
	unmarshal2 := DataStoreEntry{}
	err = json.Unmarshal(marshal2, &unmarshal2)
	if err != nil {
		return nil, errors.New("GetUser: Error unmarshalling Marshall2")
	}
	//Verify Signature
	verified, _ := VerifyDataStoreData(unmarshal2, HMACKey)
	if !verified {
		return nil, errors.New("DataStoreToOriginal: Error verifying signature")
	}

	//Decrypt user data
	result = userlib.SymDec(EncryptionKey, unmarshal2.EncrpytedCipherText)
	return result, nil
}

func VerifyDataStoreData(marshal2 DataStoreEntry, HMACKey []byte) (ok bool, err error) {

	tempHMACSig, err := userlib.HMACEval(HMACKey, marshal2.EncrpytedCipherText)
	//Verify Signature
	verified := userlib.HMACEqual(marshal2.HMACSignature, tempHMACSig)
	if !verified {
		return false, errors.New("GetUser: Error verifying signature")
	}
	return true, nil
}

func StoreToDataStore(marshal1 []byte, EncryptionKey []byte, HMACKey []byte, ID userlib.UUID) (err error) {
	iv := userlib.RandomBytes(userlib.AESBlockSizeBytes)
	ciphered := userlib.SymEnc(EncryptionKey, iv, marshal1)
	signed, err := userlib.HMACEval(HMACKey, ciphered)
	if err != nil {
		return errors.New("InitUser: Error signing user data")
	}
	marshal2, err := json.Marshal(DataStoreEntry{ciphered, signed})
	if err != nil {
		return errors.New("InitUser: Error marshalling signed user data")
	}
	userlib.DatastoreSet(ID, marshal2)

	return nil
}

func (userdata *User) generateFileKey(filename string) (result uuid.UUID, encryptionKey []byte,
	hmacKey []byte, err error) {
	//filename = hex.EncodeToString([]byte(filename))
	storageKey, err := userlib.HashKDF(userdata.PWHash[48:], []byte(filename))
	if err != nil {
		return uuid.Nil, nil, nil, errors.New("generateFileKey: Unable to Generate UUID")
	}
	result, err = uuid.FromBytes(storageKey[:16])

	encryptionKey, err = userlib.HashKDF(userdata.PWHash[16:32],
		[]byte("encryptionKeyFile")) //TODO: Does Encryption Key need to be deterministic?
	if err != nil {
		return uuid.Nil, nil, nil, errors.New("generateFileKey: Unable to Generate Encryption Key")
	}

	hmacKey, err = userlib.HashKDF(userdata.PWHash[32:48], []byte("hmacFile")) //TODO: Check Security Issue
	if err != nil {
		return uuid.Nil, nil, nil, errors.New("generateFileKey: Unable to Generate PreHash")
	}

	if err != nil {
		return uuid.Nil, nil, nil, errors.New("generateFileKey: Unable to Generate storageKey")
	}

	return result, encryptionKey, hmacKey, err
}

func (userdata *User) getShareListID(filename string) (shareListID uuid.UUID, err error) {
	filename = hex.EncodeToString([]byte(filename + "shareList"))
	shareListIDByte, err := userlib.HashKDF(userdata.PWHash[32:48], []byte(filename))
	shareListID, err = uuid.FromBytes(shareListIDByte[:16])
	if err != nil {
		return uuid.Nil, errors.New("getShareListID: Unable to Generate UUID")
	}
	return shareListID, nil

}
func (userdata *User) HybridEncryption(sharingKey []byte, sharingHMAC []byte,
	publicUser string) (cipherKey []byte, cipherKeySig []byte, cipherHMAC []byte, cipherHMACSig []byte, err error) {
	userRSA, ok := userlib.KeystoreGet(publicUser + "rsa")
	if !ok {
		return nil, nil, nil, nil, errors.New("HybridEncryption: Unable to get public key")
	}

	cipherKey, err = pkeEnc(userRSA, sharingKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	cipherHMAC, err = pkeEnc(userRSA, sharingHMAC)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	cipherKeySig, err = userlib.DSSign(userdata.SignKey, cipherKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	cipherHMACSig, err = userlib.DSSign(userdata.SignKey, cipherHMAC)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return cipherKey, cipherKeySig, cipherHMAC, cipherHMACSig, nil
}

func (userdata *User) HybridDecryptionNoVerify(cipherKey []byte, cipherHMAC []byte) (sharingKey []byte,
	sharingHMAC []byte,
	err error) {

	sharingKey, err = pkeDec(userdata.RSAPrivate, cipherKey)
	if err != nil {
		return nil, nil, errors.New("HybridDecryption: Unable to decrypt cipherKey")
	}
	sharingHMAC, err = pkeDec(userdata.RSAPrivate, cipherHMAC)
	if err != nil {
		return nil, nil, errors.New("HybridDecryption: Unable to decrypt cipherHMAC")
	}

	return sharingKey, sharingHMAC, nil
}

func (fileStruct *File) StoreToFileStruct(content []byte, encryptionKey []byte, hmacKey []byte) (err error) {
	var contentBlock, empty Block
	fileStruct.FirstBlock = uuid.New()
	contentBlock.NextBlock = uuid.New()
	fileStruct.LastBlock = contentBlock.NextBlock
	contentBlock.Data = content

	/*Store Content Block*/
	marshal1, err := json.Marshal(contentBlock)
	if err != nil {
		return errors.New("StoreFile: Failed to Marshal Content Block")
	}
	err = StoreToDataStore(marshal1, encryptionKey[:16], hmacKey[:16], fileStruct.FirstBlock)
	if err != nil {
		return errors.New("StoreFile: Failed to Store Content Block")
	}

	/*Store Empty Block*/
	marshal1, err = json.Marshal(empty)
	if err != nil {
		return errors.New("StoreFile: Failed to Marshal Empty Block")
	}
	err = StoreToDataStore(marshal1, encryptionKey[:16], hmacKey[:16], fileStruct.LastBlock)
	if err != nil {
		return errors.New("StoreFile: Failed to Store Empty Block")
	}

	return nil
}

func storeFileRecord(fileRecord FileRecord, storageKey uuid.UUID, encryptionKey []byte, hmacKey []byte) (err error) {
	marshal1, err := json.Marshal(fileRecord)
	if err != nil {
		return errors.New("CreateInvitation: Failed to Marshal File Record")
	}

	err = StoreToDataStore(marshal1, encryptionKey[:16], hmacKey[:16], storageKey)
	if err != nil {
		return err
	}
	return nil
}

func (userdata *User) decryptInviteNoVerify(inviteID uuid.UUID) (invite *Invite, err error) {
	marshal2, ok := userlib.DatastoreGet(inviteID)
	if !ok {
		return nil, errors.New("decryptInvite: Unable to get invite")
	}

	var rawDataStoreInvite DataStoreEntry
	err = json.Unmarshal(marshal2, &rawDataStoreInvite)
	if err != nil {
		return nil, errors.New("decryptInvite: Unable to unmarshal Raw DataStore Invite")
	}

	content := rawDataStoreInvite.EncrpytedCipherText

	marshal1, err := pkeDec(userdata.RSAPrivate, content)
	if err != nil {
		return nil, errors.New("decryptInvite: Unable to decrypt cipherText")
	}

	json.Unmarshal(marshal1, &invite)
	return invite, nil

}

func (invite *Invite) decryptKeysFromInvite(userdata *User) (fileID userlib.UUID, fileKey []byte, fileHMAC []byte,
	err error) {
	fileID = invite.FileID
	fileKey, fileHMAC, err = userdata.HybridDecryptionNoVerify(invite.CipherKey, invite.CipherHMAC)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	return fileID, fileKey, fileHMAC, err
}

// Following code from :https://stackoverflow.com/questions/62348923/rs256-message-too-long-for-rsa-public-key-size-error-signing-jwt
func pkeEnc(ek userlib.PKEEncKey, plaintext []byte) ([]byte, error) {
	RSAPubKey := &ek.PubKey
	if ek.KeyType != "PKE" {
		return nil, errors.New("using a non-pke key for pke")
	}

	msgLen := len(plaintext)
	step := RSAPubKey.Size() - 2*userlib.HashSizeBytes - 2
	var encryptedBytes []byte
	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		encryptedBlockBytes, err := userlib.PKEEnc(ek, plaintext[start:finish])
		if err != nil {
			return nil, err
		}

		encryptedBytes = append(encryptedBytes, encryptedBlockBytes...)
	}

	return encryptedBytes, nil
}

func pkeDec(dk userlib.PKEDecKey, ciphertext []byte) ([]byte, error) {
	RSAPrivKey := &dk.PrivKey

	if dk.KeyType != "PKE" {
		return nil, errors.New("using a non-pke for pke")
	}
	msgLen := len(ciphertext)
	step := RSAPrivKey.PublicKey.Size()
	var decryptedBytes []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		decryptedBlockBytes, err := userlib.PKEDec(dk, ciphertext[start:finish])
		if err != nil {
			return nil, err
		}

		decryptedBytes = append(decryptedBytes, decryptedBlockBytes...)
	}

	return decryptedBytes, nil
}

func (userdata *User) loadAndDelete(fileID uuid.UUID, encryptionKey []byte, hmacKey []byte) (content []byte,
	err error) {
	if err != nil {
		return nil, err
	}

	var fileStruct File
	var contentBlock Block

	var lastBlockUUID, currBlockUUID uuid.UUID

	dataJSON, ok := userlib.DatastoreGet(fileID)
	if !ok {
		return nil, errors.New("LoadFile: File not found")
	}
	result, err := DataStoreToMarshall1(dataJSON, encryptionKey[:16], hmacKey[:16])
	if err != nil {
		return nil, errors.New("LoadFile: Failed to Unmarshal Content")
	}
	json.Unmarshal(result, &fileStruct)

	currBlockUUID = fileStruct.FirstBlock
	lastBlockUUID = fileStruct.LastBlock

	for currBlockUUID != lastBlockUUID {
		dataJSON, ok = userlib.DatastoreGet(currBlockUUID)
		if !ok {
			return nil, errors.New("LoadFile: File not found")
		}
		result, err = DataStoreToMarshall1(dataJSON, encryptionKey[:16], hmacKey[:16])
		if err != nil {
			return nil, errors.New("LoadFile: Failed to Unmarshal Content")
		}
		json.Unmarshal(result, &contentBlock)
		userlib.DatastoreDelete(currBlockUUID)
		content = append(content, contentBlock.Data...)
		currBlockUUID = contentBlock.NextBlock
	}

	return content, err
}
