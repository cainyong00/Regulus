package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is marshaled into a sequence of bytes (JSON) before storing in datastore
type DatastoreValue struct {
	Ciphertext []byte
	Tag []byte
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	username string
	password string
	// RootFileKey []byte // used to generate session keys for owned files
	InvitationPrivateKey userlib.DSSignKey // used to sign/verify invitations
	AccessPrivateKey userlib.PKEDecKey // used to encrypt/decrypt invitations
	OwnedFiles map[string]map[string][]byte // personal filename: {'encryptKeyâ€™: key, â€˜signKeyâ€™: key}
	// OwnedFilesUserManagement map[string]map[uuid.UUID]map[string]interface{} // personal filename: {user id: {â€˜sessionKeyStructKeys': {'encryptKeyâ€™: key, â€˜signKeyâ€™: key}, â€˜sessionKeyStructIDâ€™: uuid of user specific session key struct}}
	OwnedFilesUserManagement map[string]map[uuid.UUID]map[string][]byte // OwnedFilesUserManagement = {personal filename: {user id: {â€˜encryptSessionKeyStructKeyâ€™: key, â€˜signSessionKeyStructKeyâ€™: key}}}
	OwnedSessionKeyStructIDs map[string]map[uuid.UUID]uuid.UUID // OwnedSessionKeyStructIDs = {personal filename: {user id: uuid of user specific session key struct}
	// AccessibleFiles map[string]map[string]interface{} // personal filename: {â€˜sessionKeyStructKeysâ€™: {'encryptKeyâ€™: key, â€˜signKeyâ€™: key}, â€˜sessionKeyStructIDâ€™: uuid of user specific session key struct}}
	AccessibleFiles map[string]map[string][]byte // AccessibleFiles = {personal filename: {â€˜encryptSessionKeyStructKeyâ€™: key, â€˜signSessionKeyStructKeyâ€™: key}}
	AccessibleSessionKeyStructIDs map[string]uuid.UUID // AccessibleSessionKeyStructIDs = {personal filename: uuid of user specific session key struct}

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type File struct {
	NextFileBlockID uuid.UUID
}

type FileBlock struct {
	FileContentBlockID uuid.UUID
	NextFileBlockID uuid.UUID
}

type FileContentBlock struct{
	FileContent []byte
}

type SessionKey struct{
	EncryptSessionKey []byte
	SignSessionKey []byte
	FileID uuid.UUID
}
// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	//check for length 0 username
	if len(username) == 0 {
		return nil, errors.New(strings.ToTitle("username length 0"))
	}
	//check if username already exists
	usernameUUID, err := GetUserUUID(username)
	if (err != nil) {
		return nil, err
	}
	_, ok := userlib.DatastoreGet(usernameUUID)
	if ok == true{
		return nil, errors.New(strings.ToTitle("username already exists"))
	}

	var userdata User
	// userdata.RootFileKey = userlib.RandomBytes(16)
	accessPublicKey, accessPrivateKey, err := userlib.PKEKeyGen() // generates public, private access key pair
	if (err != nil) {
    	return nil, err;
	}
	invitationPrivateKey, invitationPublicKey, err := userlib.DSKeyGen()
	if (err != nil) {
    	return nil, err;
	}
	userdata.AccessPrivateKey = accessPrivateKey
	userdata.InvitationPrivateKey = invitationPrivateKey
	
	// store public keys in Keystore
	accessPublicKeyID := username + "Access Public Key"
	err = userlib.KeystoreSet(accessPublicKeyID, accessPublicKey)
	if (err != nil) {
    	return nil, err;
	}
	invitationPublicKeyID := username + "Invitation Public Key"
	err = userlib.KeystoreSet(invitationPublicKeyID, invitationPublicKey)
	if (err != nil) {
    	return nil, err;
	}

	userdata.OwnedFiles = make(map[string]map[string][]byte)
	userdata.OwnedFilesUserManagement = make(map[string]map[uuid.UUID]map[string][]byte)
	userdata.OwnedSessionKeyStructIDs = make(map[string]map[uuid.UUID]uuid.UUID)
	userdata.AccessibleFiles = make(map[string]map[string][]byte)
	userdata.AccessibleSessionKeyStructIDs = make(map[string]uuid.UUID)
	
	//encrypt using symEnc
	userEncryptionKey, userSignKey := GetUserKeys(username, password)
	randomIV := userlib.RandomBytes(16)
	marshaledUserData, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}
	encryptedUserdata := userlib.SymEnc(userEncryptionKey, randomIV, marshaledUserData)
	
	//sign using HMAC
	signature, err := userlib.HMACEval(userSignKey, encryptedUserdata)
	if err != nil {
		return nil, err
	}
	//store in DataStore
	var signedUserdata DatastoreValue
	signedUserdata.Ciphertext = encryptedUserdata
	signedUserdata.Tag = signature
	signedUserdataBytes, err := json.Marshal(signedUserdata)
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(usernameUUID, signedUserdataBytes)

	// store relevant info on client
	userdata.username = username
	userdata.password = password
	


	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	//err if username doesnt exist
	userUUID, err := GetUserUUID(username)
	if err != nil {
		return nil, errors.New(strings.ToTitle("slice does not have length 16"))
	}
	_, ok := userlib.DatastoreGet(userUUID)
	if ok != true{
		return nil, errors.New(strings.ToTitle("user does not exist"))
	}

	//err if user credentials invalid
	userEncryptionKey, userSignKey := GetUserKeys(username, password)
	
	var signedUserdata DatastoreValue
	signedUserdataJSON, _ := userlib.DatastoreGet(userUUID)
	err = json.Unmarshal(signedUserdataJSON, &signedUserdata)
	if err != nil {
		return nil, err
	}
	encryptedUserdata := signedUserdata.Ciphertext
	signature := signedUserdata.Tag
	
	//err if user struct cannot be obtained due to malicious action, or integrity is compromised, or user credentials invalid
	generatedSignature, err:= userlib.HMACEval(userSignKey, encryptedUserdata)
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(generatedSignature, signature){
		return nil, errors.New(strings.ToTitle("integrity of user struct has been compromised or user credentials are invalid"))
	}

	// attempt to decrypt
	marshaledUserData := userlib.SymDec(userEncryptionKey, encryptedUserdata)
	err = json.Unmarshal(marshaledUserData, &userdata)
	if err != nil {
		return nil, err
	}
	// store relevant info on client
	userdata.username = username
	userdata.password = password
	
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	var fileStruct File
	var storageKey uuid.UUID
	var encryptSessionKey []byte
	var signSessionKey []byte
	var exists bool = false

	err = userdata.FetchUserDataToClient()

	if err != nil {
		return err
	}

	// If file exists already get corresponding session keys:
	encryptSessionKey, signSessionKey, storageKey, exists, err = userdata.CheckFileExists(filename)
	if err != nil {
		return err
	}

	// For new file:
	if !exists {
		// Create 2 session keys and file ID, and add them to owner dictionary
		// rootFileKey := userdata.RootFileKey
		encryptSessionKey = userlib.RandomBytes(16)
		signSessionKey = userlib.RandomBytes(16)
		// store session keys
		userdata.OwnedFiles[filename] = map[string][]byte{"encryptKey": encryptSessionKey, "signKey": signSessionKey}
		userdata.OwnedFilesUserManagement[filename] = make(map[uuid.UUID]map[string][]byte)
		userdata.OwnedSessionKeyStructIDs[filename] = make(map[uuid.UUID]uuid.UUID)
		storageKey, err = uuid.FromBytes(userlib.Hash([]byte(filename + userdata.username))[:16])
		if err != nil {
			return err
		}
	}
	
	// Regardless of new or old file:
	// Create and store file content block struct in Datastore. Key: random UUID, Value: Struct. Encrypt & Sign
	var fileContentBlockStruct FileContentBlock
	fileContentBlockStruct.FileContent = content
	
	randomIV := userlib.RandomBytes(16)
	marshaledFileContentBlockStruct, err := json.Marshal(fileContentBlockStruct)
	if err != nil {
		return err
	}
	encryptedContentBlock := userlib.SymEnc(encryptSessionKey, randomIV, marshaledFileContentBlockStruct)
	signature, err := userlib.HMACEval(signSessionKey, encryptedContentBlock)
	if err != nil {
		return err
	}

	var signedFileContentData DatastoreValue
	signedFileContentData.Ciphertext = encryptedContentBlock
	signedFileContentData.Tag = signature
	signedFileContentDataBytes, err := json.Marshal(signedFileContentData)
	if err != nil {
		return err
	}
	fileContentBlockKey := uuid.New()
	userlib.DatastoreSet(fileContentBlockKey, signedFileContentDataBytes)

	// Create and store file block struct in Datastore. Key: random UUID, Value: Struct. Encrypt & Sign
	var fileBlockStruct FileBlock
	fileBlockStruct.FileContentBlockID = fileContentBlockKey
	fileBlockStruct.NextFileBlockID = uuid.Nil

	randomIV = userlib.RandomBytes(16)
	marshaledFileblockStruct, err := json.Marshal(fileBlockStruct)
	if err != nil {
		return err
	}
	encryptedBlock := userlib.SymEnc(encryptSessionKey, randomIV, marshaledFileblockStruct)
	signature, err = userlib.HMACEval(signSessionKey, encryptedBlock)
	if err != nil {
		return err
	}

	var signedFileBlockData DatastoreValue
	signedFileBlockData.Ciphertext = encryptedBlock
	signedFileBlockData.Tag = signature
	signedFileBlockDataBytes, err := json.Marshal(signedFileBlockData)
	if err != nil {
		return err
	}
	fileBlockKey := uuid.New()
	userlib.DatastoreSet(fileBlockKey, signedFileBlockDataBytes)
	
	// Create and store file struct in datastore. Key: unique fileID from UUID, Value: Struct. Encrypt & sign
	fileStruct.NextFileBlockID = fileBlockKey

	randomIV = userlib.RandomBytes(16)
	marshaledFileStruct, err := json.Marshal(fileStruct)
	if err != nil {
		return err
	}
	encryptedFile := userlib.SymEnc(encryptSessionKey, randomIV, marshaledFileStruct)
	signature, err = userlib.HMACEval(signSessionKey, encryptedFile)
	if err != nil {
		return err
	}

	var signedFileData DatastoreValue
	signedFileData.Ciphertext = encryptedFile
	signedFileData.Tag = signature
	signedFileDataBytes, err := json.Marshal(signedFileData)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, signedFileDataBytes)
	
	err = userdata.UpdateUserDataToServer()
	if err != nil {
		return err
	}

	return
}

func (userdata *User) AppendToFile(filename string, content []byte) (err error) {
	var storageKey uuid.UUID
	var fileStruct File
	var encryptSessionKey []byte
	var signSessionKey []byte
	var exists bool = false

	err = userdata.FetchUserDataToClient()

	if err != nil {
		return err
	}

	// If file exists already get corresponding session keys:
	// check in owned files and accessible files
	encryptSessionKey, signSessionKey, storageKey, exists, err = userdata.CheckFileExists(filename)
	if err != nil {
		return err
	}

	if exists == false {
		return errors.New(strings.ToTitle("file doesn't exist"))
	}

	// download and decrypt outermost file struct
	fileStruct, err = RetrieveDecryptedFileStruct(storageKey, signSessionKey, encryptSessionKey)

	if err != nil {
		return err
	}
	// Get first file block struct
	fileBlockStruct, err := RetrieveDecryptedFileBlockStruct(fileStruct.NextFileBlockID, signSessionKey, encryptSessionKey)
	if err != nil{
		return err
	}
	
	// Traverse til end
	var lastFileBlockStructUUID uuid.UUID = fileStruct.NextFileBlockID
	for fileBlockStruct.NextFileBlockID != uuid.Nil {
		lastFileBlockStructUUID = fileBlockStruct.NextFileBlockID
		fileBlockStruct, err = RetrieveDecryptedFileBlockStruct(fileBlockStruct.NextFileBlockID, signSessionKey, encryptSessionKey)
		if err != nil {
			return err
		}
	}
	// make file content block struct, encrypt & sign, store in datastore
	var fileContentBlockStruct FileContentBlock
	fileContentBlockStruct.FileContent = content
	
	randomIV := userlib.RandomBytes(16)
	marshaledFileContentBlockStruct, err := json.Marshal(fileContentBlockStruct)
	if err != nil{
		return err
	}
	encryptedContentBlock := userlib.SymEnc(encryptSessionKey, randomIV, marshaledFileContentBlockStruct)
	signature, err := userlib.HMACEval(signSessionKey, encryptedContentBlock)
	if err != nil{
		return err
	}

	var signedFileContentData DatastoreValue
	signedFileContentData.Ciphertext = encryptedContentBlock
	signedFileContentData.Tag = signature
	signedFileContentDataBytes, err := json.Marshal(signedFileContentData)
	if err != nil {
		return err
	}
	fileContentBlockKey := uuid.New()
	userlib.DatastoreSet(fileContentBlockKey, signedFileContentDataBytes)

	//make file block struct, encrypt&sign, store in datastore

	var newFileBlockStruct FileBlock
	newFileBlockStruct.FileContentBlockID = fileContentBlockKey
	newFileBlockStruct.NextFileBlockID = uuid.Nil

	randomIV = userlib.RandomBytes(16)
	marshaledFileblockStruct, err := json.Marshal(newFileBlockStruct)
	if err != nil{
		return err
	}

	encryptedBlock := userlib.SymEnc(encryptSessionKey, randomIV, marshaledFileblockStruct)
	signature, err = userlib.HMACEval(signSessionKey, encryptedBlock)
	if err != nil{
		return err
	}


	var signedFileBlockData DatastoreValue
	signedFileBlockData.Ciphertext = encryptedBlock
	signedFileBlockData.Tag = signature
	signedFileBlockDataBytes, err := json.Marshal(signedFileBlockData)
	if err != nil {
		return err
	}
	fileBlockKey := uuid.New()
	userlib.DatastoreSet(fileBlockKey, signedFileBlockDataBytes)
	
	// update last file block (before the newly appended block)
	fileBlockStruct.NextFileBlockID = fileBlockKey
	// store last file block struct to datastore
	randomIV = userlib.RandomBytes(16)
	marshaledLastFileBlockStruct, err := json.Marshal(fileBlockStruct)
	if err != nil{
		return err
	}
	encryptedLastBlock := userlib.SymEnc(encryptSessionKey, randomIV, marshaledLastFileBlockStruct)
	signature, err = userlib.HMACEval(signSessionKey, encryptedLastBlock)
	if err != nil{
		return err
	}
	var signedLastFileBlockData DatastoreValue
	signedLastFileBlockData.Ciphertext = encryptedLastBlock
	signedLastFileBlockData.Tag = signature
	signedLastFileblockDatabytes, err := json.Marshal(signedLastFileBlockData)
	if err != nil{
		return err
	}
	userlib.DatastoreSet(lastFileBlockStructUUID, signedLastFileblockDatabytes)
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	var storageKey uuid.UUID
	var fileStruct File

	var encryptSessionKey []byte
	var signSessionKey []byte
	var exists bool = false

	err = userdata.FetchUserDataToClient()
	if err != nil {
		return nil, err
	}

	// If file exists already get corresponding session keys:
	// check in owned files and accessible files
	encryptSessionKey, signSessionKey, storageKey, exists, err = userdata.CheckFileExists(filename)
	if err != nil {
		return nil, err
	}

	if exists == false {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	
	// download and decrypt
	fileStruct, err = RetrieveDecryptedFileStruct(storageKey, signSessionKey, encryptSessionKey)
	if err != nil {
		return nil, err
	}
	
	// Traverse file and download blocks
	var nextBlockID = fileStruct.NextFileBlockID
	var hasNextBlock bool = (nextBlockID != uuid.Nil)
	for hasNextBlock {
		fileBlockStruct, err := RetrieveDecryptedFileBlockStruct(nextBlockID, signSessionKey, encryptSessionKey)
		if err != nil{

			return nil, err
		}
	
		fileContentBlockStruct, err := RetrieveDecryptedFileContentBlockStruct(fileBlockStruct.FileContentBlockID, signSessionKey, encryptSessionKey)
		if err != nil{
			return nil, err
		}	
		// add new content
		content = append(content, fileContentBlockStruct.FileContent...)
		
		// move to next block
		nextBlockID = fileBlockStruct.NextFileBlockID
		hasNextBlock = (nextBlockID != uuid.Nil)
	}
	return content, nil
}

type Invitation struct {
	EncryptSessionKeyStructKey []byte
	SignSessionKeyStructKey []byte
	SessionKeyStructID uuid.UUID
}

type InvitationWrapper struct{
	EncryptedInvitation []byte
	EncryptedInvitationSignature []byte
	EncryptedEncryptInvitationKey []byte
	EncryptedSignInvitationKey []byte
	EncryptedEncryptInvitationKeySignature []byte
	EncryptedSignInvitationKeySignature []byte
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	
	var encryptSessionKey []byte
	var signSessionKey []byte
	var exists bool = false
	var isOwner bool = false
	var storageKey uuid.UUID
	
	err = userdata.FetchUserDataToClient()
	if err != nil {
		return uuid.Nil, err
	}
	// If file exists already get corresponding session keys
	// check in owned files and accessible files
	encryptSessionKey, signSessionKey, storageKey, exists, err = userdata.CheckFileExists(filename)
	if err != nil {
		return uuid.Nil, err
	}
	if exists == false {
		return uuid.Nil, errors.New(strings.ToTitle("file not found"))
	}
	// download and decrypt outermost file struct to verify not revoked
	_, err = RetrieveDecryptedFileStruct(storageKey, signSessionKey, encryptSessionKey)
	if err != nil {
		return uuid.Nil, err
	}

	// check given recipientUsername exists
	recipientUUID, err := GetUserUUID(recipientUsername)
	if err != nil{
		return uuid.Nil, err
	}

	_, ok := userlib.DatastoreGet(recipientUUID)
	if !ok {
		return uuid.Nil, errors.New(strings.ToTitle("recipientUser not found"))
	}

	// check if user is owner of file
	_, isOwner = userdata.OwnedFiles[filename]

	var sessionKeyStructID uuid.UUID
	var encryptSessionKeyStructKey []byte
	var signSessionKeyStructKey []byte

	// If user is owner, create necessary keys and structs
	if isOwner == true {
		storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.username))[:16])
		if err != nil {
			return uuid.Nil, err
		}

		// Generate user-specific keys from RandomBytes
		encryptSessionKeyStructKey = userlib.RandomBytes(16)
		signSessionKeyStructKey = userlib.RandomBytes(16)
		
		// Create session key struct
		var sessionKeyStruct SessionKey
		sessionKeyStructID = uuid.New()
		sessionKeyStruct.EncryptSessionKey = encryptSessionKey
		sessionKeyStruct.SignSessionKey = signSessionKey
		sessionKeyStruct.FileID = storageKey
		
		// Encrypt with user-specific key
		randomIV := userlib.RandomBytes(16)
		marshaledSessionKeyStruct, err := json.Marshal(sessionKeyStruct)
		if err != nil{
			return uuid.Nil, err
		}
		encryptedSessionKeyStruct := userlib.SymEnc(encryptSessionKeyStructKey, randomIV, marshaledSessionKeyStruct)
		
		// Sign using HMAC
		signature, err := userlib.HMACEval(signSessionKeyStructKey, encryptedSessionKeyStruct)
		if err != nil{
			return uuid.Nil, err
		}
	
		// Store in DataStore
		var signedSessionKeyStruct DatastoreValue
		signedSessionKeyStruct.Ciphertext = encryptedSessionKeyStruct
		signedSessionKeyStruct.Tag = signature
		signedSessionKeyStructBytes, err := json.Marshal(signedSessionKeyStruct)
		if err != nil {
			return uuid.Nil, err
		}
		userlib.DatastoreSet(sessionKeyStructID, signedSessionKeyStructBytes)
		// Update owner dictionary
		userdata.OwnedFilesUserManagement[filename][recipientUUID] = map[string][]byte{"encryptSessionKeyStructKey": encryptSessionKeyStructKey, "signSessionKeyStructKey": signSessionKeyStructKey}
		userdata.OwnedSessionKeyStructIDs[filename] = map[uuid.UUID]uuid.UUID{recipientUUID: sessionKeyStructID}

	} else { // If not owner, retrieve relevant keys and structs
		sessionKeyStructID = userdata.AccessibleSessionKeyStructIDs[filename]
		sessionKeyStructKeys := userdata.AccessibleFiles[filename]
		encryptSessionKeyStructKey = sessionKeyStructKeys["encryptSessionKeyStructKey"]
		signSessionKeyStructKey = sessionKeyStructKeys["signSessionKeyStructKey"]
	}
	
	// Create invitation object
	var invitation Invitation
	invitation.EncryptSessionKeyStructKey = encryptSessionKeyStructKey
	invitation.SignSessionKeyStructKey = signSessionKeyStructKey
	invitation.SessionKeyStructID = sessionKeyStructID
	
	// Encrypt invitation object with access public key of the recipient
	accessPublicKey, ok := userlib.KeystoreGet(recipientUsername + "Access Public Key")
	
	if !ok {
		return uuid.Nil, errors.New(strings.ToTitle("recipientUser has no public key"))
	}
	marshaledInvitation, err := json.Marshal(invitation)
	if err != nil{
		return uuid.Nil, err
	}
	
	// generate 2 new symmetric keys
	encryptInvitationKey := userlib.RandomBytes(16)
	signInvitationKey := userlib.RandomBytes(16)
	randomIV := userlib.RandomBytes(16)

	// encrypt marshaledInvitation with encryptInvitationKey
	encryptedInvitation := userlib.SymEnc(encryptInvitationKey, randomIV, marshaledInvitation)
	// sign the encrypted marshaledInvitation with signInvitationKey
	signature, err := userlib.HMACEval(signInvitationKey, encryptedInvitation)
	if err != nil{
		return uuid.Nil, err
	}
	// encrypt symmetric key with access public key of the recipient
	encryptedEncryptInvitationKey, err := userlib.PKEEnc(accessPublicKey, encryptInvitationKey)
	if err != nil{
		return uuid.Nil, err
	}
	encryptedSignInvitationKey, err := userlib.PKEEnc(accessPublicKey, signInvitationKey)
	if err != nil{
		return uuid.Nil, err
	}
	// sign symmetric key with userâ€™s invitation private key
	encryptInvitationKeySignature, err := userlib.DSSign(userdata.InvitationPrivateKey, encryptedEncryptInvitationKey)
	if err != nil{
		return uuid.Nil, err
	}
	signInvitationKeySignature, err := userlib.DSSign(userdata.InvitationPrivateKey, encryptedSignInvitationKey)
	if err != nil{
		return uuid.Nil, err
	}

	// Store in Datastore
	var invitationData InvitationWrapper
	invitationData.EncryptedInvitation = encryptedInvitation
	invitationData.EncryptedInvitationSignature = signature
	invitationData.EncryptedEncryptInvitationKey = encryptedEncryptInvitationKey
	invitationData.EncryptedSignInvitationKey = encryptedSignInvitationKey
	invitationData.EncryptedSignInvitationKeySignature = signInvitationKeySignature
	invitationData.EncryptedEncryptInvitationKeySignature = encryptInvitationKeySignature
	// pass both encrypted marshaledInvitation and both encrypted symmetric keys to recipient

	invitationPtr = uuid.New()
	marshaledInvitationData, err := json.Marshal(invitationData)
	if err != nil {
		return uuid.Nil, err
	}
	userlib.DatastoreSet(invitationPtr, marshaledInvitationData)

	err = userdata.UpdateUserDataToServer()
	if err != nil {
		return uuid.Nil, err
	}

	return invitationPtr, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) (err error) {

	err = userdata.FetchUserDataToClient()
	
	if err != nil {
		return err
	}

	// Check if filename already exists in user's namespace
	// 1) check in owned files
	_, ok := userdata.OwnedFiles[filename] // {'encryptKeyâ€™: key, â€˜signKeyâ€™: key}
	if ok { // exists
		return errors.New(strings.ToTitle("file with given name already exists"))
	}
	// 2) check in non-owned accessible files
	_, ok = userdata.AccessibleFiles[filename]
	if ok { // exists
		return errors.New(strings.ToTitle("file with given name already exists"))
	}

	// Get invitation object
	downloadedInvitation, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New(strings.ToTitle("invitation not found"))
	}
	var encryptedSignedInvitation InvitationWrapper
	err = json.Unmarshal(downloadedInvitation, &encryptedSignedInvitation)
	if err != nil {
		return err
	}
	encryptedInvitation := encryptedSignedInvitation.EncryptedInvitation
	signature := encryptedSignedInvitation.EncryptedInvitationSignature
	encryptedEncryptInvitationKey := encryptedSignedInvitation.EncryptedEncryptInvitationKey
	encryptedSignInvitationKey := encryptedSignedInvitation.EncryptedSignInvitationKey
	signInvitationKeySignature := encryptedSignedInvitation.EncryptedSignInvitationKeySignature
	encryptInvitationKeySignature := encryptedSignedInvitation.EncryptedEncryptInvitationKeySignature

	// Get sender's invitation public key
	invitationPublicKey, ok := userlib.KeystoreGet(senderUsername + "Invitation Public Key")
	if !ok {
		return errors.New(strings.ToTitle("senderUser has no invitation public key"))
	}

	// verify integrity of encryptedEncryptInvitationKey and encryptedSignInvitationKey
	err = userlib.DSVerify(invitationPublicKey, encryptedEncryptInvitationKey, encryptInvitationKeySignature)
	if err != nil {
		return err
	}
	err = userlib.DSVerify(invitationPublicKey, encryptedSignInvitationKey, signInvitationKeySignature)
	if err != nil {
		return err
	}

	// Decrypt encryptedEncryptInvitationKey and encryptedSignInvitationKey with own access private key
	encryptInvitationKey, err := userlib.PKEDec(userdata.AccessPrivateKey, encryptedEncryptInvitationKey)
	if err != nil{
		return err
	}
	signInvitationKey, err := userlib.PKEDec(userdata.AccessPrivateKey, encryptedSignInvitationKey)
	if err != nil{
		return err
	}
	
	// Verify HMAC of invitation was created by senderusername with signInvitationKey
	generatedSignature, err := userlib.HMACEval(signInvitationKey, encryptedInvitation)
	if err != nil{
		return err
	}
	if !userlib.HMACEqual(generatedSignature, signature) {
		return errors.New(strings.ToTitle("Invitation was not created by senderUser"))
	}

	// Decrypt invitation object with encryptInvitationKey to get session key struct keys
	var invitation Invitation
	marshaledInvitation := userlib.SymDec(encryptInvitationKey, encryptedInvitation)
	err = json.Unmarshal(marshaledInvitation, &invitation)

	if err != nil{
		return err
	}
	encryptSessionKeyStructKey := invitation.EncryptSessionKeyStructKey
	signSessionKeyStructKey := invitation.SignSessionKeyStructKey
	sessionKeyStructID := invitation.SessionKeyStructID

	accessibleFileInfo := make(map[string][]byte)
	accessibleFileInfo["encryptSessionKeyStructKey"] = encryptSessionKeyStructKey
	accessibleFileInfo["signSessionKeyStructKey"] = signSessionKeyStructKey

	// Validate that the senderUser was not revoked from the file
	err = ValidateAccessToFile(accessibleFileInfo, sessionKeyStructID)

	if err != nil {
		return err
	}
	
	// Store in user's accessibleFiles map and AccessibleSessionKeyStructIDs map
	userdata.AccessibleFiles[filename] = accessibleFileInfo
	userdata.AccessibleSessionKeyStructIDs[filename] = sessionKeyStructID
	err = userdata.UpdateUserDataToServer()

	if err != nil {
		return err
	}

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) (err error) {
	
	err = userdata.FetchUserDataToClient()
	if err != nil {
		return err
	}

	// Check filename exists in userdata's owner dictionary
	filedata, isOwner := userdata.OwnedFiles[filename]
	if !isOwner {
		return errors.New(strings.ToTitle("user does not own the file"))
	}

	// retrieve original session keys for decrypting file
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.username))[:16])
	if err != nil {
		return err
	}
	prevEncryptSessionKey := filedata["encryptKey"]
	prevSignSessionKey := filedata["signKey"]
	recipientUUID, err := GetUserUUID(recipientUsername)
	if err != nil{
		return err
	}
	//OwnedFilesUserManagement map[string]map[uuid.UUID]map[string][]byte // OwnedFilesUserManagement = {personal filename: {user id: {â€˜encryptSessionKeyStructKeyâ€™: key, â€˜signSessionKeyStructKeyâ€™: key}}}
	//OwnedSessionKeyStructIDs map[string]map[uuid.UUID]uuid.UUID // OwnedSessionKeyStructIDs = {personal filename: {user id: uuid of user specific session key struct}
	
	// Error if filename is not currently shared with recipientUsername
	found := false
	if recipients, ok := userdata.OwnedFilesUserManagement[filename]; ok {
		// recipients = {user id: {â€˜encryptSessionKeyStructKeyâ€™: key, â€˜signSessionKeyStructKeyâ€™: key}}
		if _, ok := recipients[recipientUUID]; ok {
			found = true
			
		}
	}
	if !found {
		return errors.New(strings.ToTitle("recipient user has no access to the file"))
	}

	// Delete user being revoked from owner dictionary
	
	delete(userdata.OwnedFilesUserManagement[filename], recipientUUID)
	delete(userdata.OwnedSessionKeyStructIDs[filename], recipientUUID)

	//generate new session keys
	encryptSessionKey := userlib.RandomBytes(16)
	signSessionKey := userlib.RandomBytes(16)

	// modify owner dict
	userdata.OwnedFiles[filename] = map[string][]byte{"encryptKey": encryptSessionKey, "signKey": signSessionKey}

	// edit session key structs for users who still have access
	var currSessionKeyStructID uuid.UUID
	var signedSessionKeyStruct DatastoreValue
	var encryptedSessionKeyStruct []byte
	var currSessionKeyStruct SessionKey

	if recipients, ok := userdata.OwnedFilesUserManagement[filename]; ok{
		for currUserID, recipientData := range recipients {
			// Get session key struct for user
			currSessionKeyStructID = userdata.OwnedSessionKeyStructIDs[filename][currUserID]
			signedSessionKeyStructJSON, ok := userlib.DatastoreGet(currSessionKeyStructID)
			if ok != true{
				return errors.New(strings.ToTitle("session key struct not found"))
			}
			err = json.Unmarshal(signedSessionKeyStructJSON, &signedSessionKeyStruct)
			if err != nil {
				return err
			}
			encryptedSessionKeyStruct = signedSessionKeyStruct.Ciphertext
			signature := signedSessionKeyStruct.Tag

			//get user-specific keys
			currUserSpecificEncryptKey := recipientData["encryptSessionKeyStructKey"]
			currUserSpecificSignKey := recipientData["signSessionKeyStructKey"]
			
			//check integrity of the session key struct
			generatedSignature, err := userlib.HMACEval(currUserSpecificSignKey, encryptedSessionKeyStruct)
			if err != nil {
				return err
			}
			if !userlib.HMACEqual(generatedSignature, signature){
				return errors.New(strings.ToTitle("integrity of session key struct has been compromised"))
			}
			//update the session key struct
			marshaledSessionKeyStruct := userlib.SymDec(currUserSpecificEncryptKey, encryptedSessionKeyStruct)
			err = json.Unmarshal(marshaledSessionKeyStruct, &currSessionKeyStruct)
			if err != nil {
				return err
			}
			currSessionKeyStruct.EncryptSessionKey = encryptSessionKey
			currSessionKeyStruct.SignSessionKey = signSessionKey
			//sign and encrypt the session key struct
			marshaledSessionKeyStruct, err = json.Marshal(currSessionKeyStruct)
			if err != nil {
				return err
			}
			randomIV := userlib.RandomBytes(16)
			encryptedSessionKeyStruct = userlib.SymEnc(currUserSpecificEncryptKey, randomIV, marshaledSessionKeyStruct)
			
			signature, err = userlib.HMACEval(currUserSpecificSignKey, encryptedSessionKeyStruct)
			if err != nil {
				return err
			}
			signedSessionKeyStruct.Ciphertext = encryptedSessionKeyStruct
			signedSessionKeyStruct.Tag = signature
			signedSessionKeyStructBytes, err := json.Marshal(signedSessionKeyStruct)
			if err != nil {
				return err
			}
			userlib.DatastoreSet(currSessionKeyStructID, signedSessionKeyStructBytes)
		}
	}
	
	// Decrypt the file struct
	fileStruct, err := RetrieveDecryptedFileStruct(storageKey, prevSignSessionKey, prevEncryptSessionKey)
	if err != nil {
		return err
	}
	
	// Reencrypt file struct and sign
	randomIV := userlib.RandomBytes(16)
	marshaledFileStruct, err := json.Marshal(fileStruct)
	if err != nil {
		return err
	}
	encryptedFiledata := userlib.SymEnc(encryptSessionKey, randomIV, marshaledFileStruct)
	signature, err := userlib.HMACEval(signSessionKey, encryptedFiledata)
	if err != nil {
		return err
	}

	var signedFileData DatastoreValue
	signedFileData.Ciphertext = encryptedFiledata
	signedFileData.Tag = signature
	signedFileDataBytes, err := json.Marshal(signedFileData)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, signedFileDataBytes)

	// Traverse file and decrypt / reencrypt blocks
	var nextBlockID = fileStruct.NextFileBlockID
	var hasNextBlock bool = (nextBlockID != uuid.Nil)
	for hasNextBlock {
		fileBlockStruct, err := RetrieveDecryptedFileBlockStruct(nextBlockID, prevSignSessionKey, prevEncryptSessionKey)
		if err != nil {
			return err
		}
		fileContentBlockStruct, err := RetrieveDecryptedFileContentBlockStruct(fileBlockStruct.FileContentBlockID, prevSignSessionKey, prevEncryptSessionKey)
		if err != nil {
			return err
		}

		// reencrypt file content block
		randomIV := userlib.RandomBytes(16)
		marshaledFileContentBlockStruct, err := json.Marshal(fileContentBlockStruct)
		if err != nil {
			return err
		}
		encryptedContentBlock := userlib.SymEnc(encryptSessionKey, randomIV, marshaledFileContentBlockStruct)
		signature, err := userlib.HMACEval(signSessionKey, encryptedContentBlock)
		if err != nil {
			return err
		}

		var signedFileContentData DatastoreValue
		signedFileContentData.Ciphertext = encryptedContentBlock
		signedFileContentData.Tag = signature
		signedFileContentDataBytes, err := json.Marshal(signedFileContentData)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(fileBlockStruct.FileContentBlockID, signedFileContentDataBytes)

		// reencrypt file block
		randomIV = userlib.RandomBytes(16)
		marshaledFileBlockStruct, err := json.Marshal(fileBlockStruct)
		if err != nil {
			return err
		}
		encryptedBlock := userlib.SymEnc(encryptSessionKey, randomIV, marshaledFileBlockStruct)
		signature, err = userlib.HMACEval(signSessionKey, encryptedBlock)
		if err != nil {
			return err
		}

		var signedFileBlockData DatastoreValue
		signedFileBlockData.Ciphertext = encryptedBlock
		signedFileBlockData.Tag = signature
		signedFileBlockDataBytes, err := json.Marshal(signedFileBlockData)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(nextBlockID, signedFileBlockDataBytes)
		
		// move to next block
		nextBlockID = fileBlockStruct.NextFileBlockID
		hasNextBlock = (nextBlockID != uuid.Nil)
	}

	err = userdata.UpdateUserDataToServer()
	if err != nil {
		return err
	}
	
	return nil
}

// Helper functions

func GetUserUUID(username string) (uuid.UUID, error) {
	hashedUsername := userlib.Hash([]byte(username))
	hashedUsername = hashedUsername[:16]
	usernameUUID, err := uuid.FromBytes(hashedUsername)
	if err != nil{
		return uuid.Nil, err
	}
	return usernameUUID, nil
}

func GetUserKeys (username string, password string) ([]byte, []byte) {
	hashedUsername := userlib.Hash([]byte(username))
	userKey := userlib.Argon2Key([]byte(password), hashedUsername, 32)
	userEncryptionKey := userKey[:16]
	userSignKey := userKey[16:]
	return userEncryptionKey, userSignKey
}

func ParseAccessibleFileInfo (sessionKeyStructID uuid.UUID, sessionKeyStructEncryptKey []byte, sessionKeyStructSignKey []byte) (encryptSessionKey []byte, signSessionKey []byte, fileID uuid.UUID, err error) {
	// get session keys from session key struct
	// and figure out where file is
	downloadSignedSessionKeyInfo, ok := userlib.DatastoreGet(sessionKeyStructID)
	if !ok {
		return nil, nil, uuid.Nil, errors.New(strings.ToTitle("session key info not found"))
	}
	var encryptedSignedSessionKeyInfo DatastoreValue
	err = json.Unmarshal(downloadSignedSessionKeyInfo, &encryptedSignedSessionKeyInfo)
	if err != nil {
		return nil, nil, uuid.Nil, err
	}
	encryptedSessionKeyInfo := encryptedSignedSessionKeyInfo.Ciphertext
	signature := encryptedSignedSessionKeyInfo.Tag
	generatedSignature, err := userlib.HMACEval(sessionKeyStructSignKey, encryptedSessionKeyInfo)
	if err != nil {
		return nil, nil, uuid.Nil, err
	}
	if !userlib.HMACEqual(generatedSignature, signature){
		return nil, nil, uuid.Nil, errors.New(strings.ToTitle("integrity of session key struct has been compromised"))
	}
	marshaledSessionKeyInfo := userlib.SymDec(sessionKeyStructEncryptKey, encryptedSessionKeyInfo)
	var sessionKeyInfo SessionKey
	json.Unmarshal(marshaledSessionKeyInfo, &sessionKeyInfo)
	encryptSessionKey = sessionKeyInfo.EncryptSessionKey
	signSessionKey = sessionKeyInfo.SignSessionKey
	fileID = sessionKeyInfo.FileID

	return encryptSessionKey, signSessionKey, fileID, nil
}

func ValidateAccessToFile (accessibleFileInfo map[string][]byte, sessionKeyStructID uuid.UUID) (err error) {
	sessionKeyStructEncryptKey := accessibleFileInfo["encryptSessionKeyStructKey"]
	sessionKeyStructSignKey := accessibleFileInfo["signSessionKeyStructKey"]
	
	_, signSessionKey, storageKey, err := ParseAccessibleFileInfo(sessionKeyStructID, sessionKeyStructEncryptKey, sessionKeyStructSignKey)
	if err != nil {
		return err
	}
	// download and validate signature of outermost file struct
	downloadSignedFile, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return errors.New(strings.ToTitle("the file doesn't exist (validate)"))
	}
	var encryptedSignedFiledata DatastoreValue
	err = json.Unmarshal(downloadSignedFile, &encryptedSignedFiledata)
	if err != nil {
		return err
	}
	encryptedFiledata := encryptedSignedFiledata.Ciphertext
	signature := encryptedSignedFiledata.Tag
	generatedSignature, err := userlib.HMACEval(signSessionKey, encryptedFiledata)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(generatedSignature, signature){
		return errors.New(strings.ToTitle("unable to validate access to file"))
	}
	return nil
}

func (userdata *User) CheckFileExists (filename string) (encryptSessionKey []byte, signSessionKey []byte, storageKey uuid.UUID, exists bool, err error) {
	exists = false

	// If file exists already get corresponding session keys:
	// 1) check in owned files
	ownedFileInfo, ok := userdata.OwnedFiles[filename] // {'encryptKeyâ€™: key, â€˜signKeyâ€™: key}
	if ok { // exists
		exists = true
		storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.username))[:16])
		if err != nil {
			return nil, nil, uuid.Nil, exists, err
		}
		encryptSessionKey = ownedFileInfo["encryptKey"]
		signSessionKey = ownedFileInfo["signKey"]
		return encryptSessionKey, signSessionKey, storageKey, exists, nil
	}
	// 2) check in non-owned accessible files
	accessibleFileInfo, ok := userdata.AccessibleFiles[filename] // {â€˜sessionKeyStructKeysâ€™: {'encryptKeyâ€™: key, â€˜signKeyâ€™: key}, â€˜sessionKeyStructIDâ€™: uuid of user specific session key struct}
	if ok { // exists
		exists = true
		sessionKeyStructEncryptKey := accessibleFileInfo["encryptSessionKeyStructKey"]
		sessionKeyStructSignKey := accessibleFileInfo["signSessionKeyStructKey"]
		encryptSessionKey, signSessionKey, storageKey, err = ParseAccessibleFileInfo(userdata.AccessibleSessionKeyStructIDs[filename], sessionKeyStructEncryptKey, sessionKeyStructSignKey)
		if err != nil {
			return nil, nil, uuid.Nil, exists, err
		}
		return encryptSessionKey, signSessionKey, storageKey, exists, nil
	}
	return nil, nil, uuid.Nil, false, nil
}

func RetrieveDecryptedFileStruct (fileID uuid.UUID, signSessionKey []byte, encryptSessionKey []byte) (fileStruct File, err error) {
	downloadSignedFile, ok := userlib.DatastoreGet(fileID)
	if !ok {
		return fileStruct, errors.New(strings.ToTitle("the file doesn't exist (file)"))
	}
	var encryptedSignedFiledata DatastoreValue
	err = json.Unmarshal(downloadSignedFile, &encryptedSignedFiledata)
	if err != nil {
		return fileStruct, err
	}
	encryptedFiledata := encryptedSignedFiledata.Ciphertext
	signature := encryptedSignedFiledata.Tag
	generatedSignature, err := userlib.HMACEval(signSessionKey, encryptedFiledata)
	if err != nil {
		return fileStruct, err
	}
	if !userlib.HMACEqual(generatedSignature, signature){
		return fileStruct, errors.New(strings.ToTitle("integrity of file struct has been compromised"))
	}
	marshaledFileStruct := userlib.SymDec(encryptSessionKey, encryptedFiledata)
	err = json.Unmarshal(marshaledFileStruct, &fileStruct)
	return fileStruct, nil
}

func RetrieveDecryptedFileBlockStruct (fileBlockID uuid.UUID, signSessionKey []byte, encryptSessionKey[]byte) (fileBlockStruct FileBlock, err error) {
	downloadSignedFileBlock, ok := userlib.DatastoreGet(fileBlockID)
	if !ok {
		return fileBlockStruct, errors.New(strings.ToTitle("the file doesn't exist (file block)"))
	}
	var encryptedSignedFileBlockData DatastoreValue
	err = json.Unmarshal(downloadSignedFileBlock, &encryptedSignedFileBlockData)
	if err != nil {
		return fileBlockStruct, err
	}
	encryptedFileBlockData := encryptedSignedFileBlockData.Ciphertext
	signature := encryptedSignedFileBlockData.Tag
	generatedSignature, err := userlib.HMACEval(signSessionKey, encryptedFileBlockData)
	if err != nil {
		return fileBlockStruct, err
	}
	if !userlib.HMACEqual(generatedSignature, signature){
		return fileBlockStruct, errors.New(strings.ToTitle("integrity of file block has been compromised"))
	}
	marshaledFileBlockStruct := userlib.SymDec(encryptSessionKey, encryptedFileBlockData)
	err = json.Unmarshal(marshaledFileBlockStruct, &fileBlockStruct)
	return fileBlockStruct, nil
}

func RetrieveDecryptedFileContentBlockStruct (fileContentBlockID uuid.UUID, signSessionKey []byte, encryptSessionKey []byte) (fileContentBlockStruct FileContentBlock, err error) {
	downloadSignedFileContentBlock, ok := userlib.DatastoreGet(fileContentBlockID)
	if !ok {
		return fileContentBlockStruct, errors.New(strings.ToTitle("the file doesn't exist (file content block)"))
	}
	var encryptedSignedFileContentBlockData DatastoreValue
	err = json.Unmarshal(downloadSignedFileContentBlock, &encryptedSignedFileContentBlockData)
	if err != nil {
		return fileContentBlockStruct, err
	}
	encryptedFileContentBlockData := encryptedSignedFileContentBlockData.Ciphertext
	signature := encryptedSignedFileContentBlockData.Tag
	generatedSignature, err := userlib.HMACEval(signSessionKey, encryptedFileContentBlockData)
	if err != nil {
		return fileContentBlockStruct, err
	}
	if !userlib.HMACEqual(generatedSignature, signature){
		return fileContentBlockStruct, errors.New(strings.ToTitle("integrity of file content block has been compromised"))
	}
	marshaledFileContentBlockStruct := userlib.SymDec(encryptSessionKey, encryptedFileContentBlockData)
	err = json.Unmarshal(marshaledFileContentBlockStruct, &fileContentBlockStruct)
	return fileContentBlockStruct, nil
}

func (userdata *User) FetchUserDataToClient() (err error) {
	var userUUID uuid.UUID
	userUUID, err = GetUserUUID(userdata.username)
	

	if err != nil {
		return err
	}
	
	userEncryptionKey, userSignKey := GetUserKeys(userdata.username, userdata.password)
	
	signedUserDatabytes, ok := userlib.DatastoreGet(userUUID)
	if ok != true{
		return errors.New(strings.ToTitle("user does not exist"))
	}
	var signedUserdata DatastoreValue
	err = json.Unmarshal(signedUserDatabytes, &signedUserdata)
	if err != nil {
		return err
	}

	encryptedUserdata := signedUserdata.Ciphertext
	signature := signedUserdata.Tag

	//check the integrity of the user data
	generatedSignature, err := userlib.HMACEval(userSignKey, encryptedUserdata)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(generatedSignature, signature){
		return errors.New(strings.ToTitle("integrity of user struct has been compromised or user credentials are invalid"))
	}
	
	// attempt to decrypt
	var newUserData *User
	marshaledUserData := userlib.SymDec(userEncryptionKey, encryptedUserdata)
	err = json.Unmarshal(marshaledUserData, &newUserData)
	if err != nil {
		return err
	}
	userdata.OwnedFiles = newUserData.OwnedFiles
	userdata.OwnedFilesUserManagement = newUserData.OwnedFilesUserManagement
	userdata.OwnedSessionKeyStructIDs = newUserData.OwnedSessionKeyStructIDs
	userdata.AccessibleFiles = newUserData.AccessibleFiles
	userdata.AccessibleSessionKeyStructIDs = newUserData.AccessibleSessionKeyStructIDs
	
	return nil
}

func (userdata *User) UpdateUserDataToServer() (err error) {
	// Get UUID and relevant credentials
	userUUID, err := GetUserUUID(userdata.username)
	if err != nil {
		return err
	}
	userEncryptionKey, userSignKey := GetUserKeys(userdata.username, userdata.password)

	// encrypt client version of userdata
	randomIV := userlib.RandomBytes(16)
	marshaledUserData, err := json.Marshal(userdata)
	if err != nil {
		return err
	}
	encryptedUserdata := userlib.SymEnc(userEncryptionKey, randomIV, marshaledUserData)

	//sign using HMAC
	signature, err := userlib.HMACEval(userSignKey, encryptedUserdata)
	if err != nil {
		return err
	}

	//store in DataStore
	var signedUserdata DatastoreValue
	signedUserdata.Ciphertext = encryptedUserdata
	signedUserdata.Tag = signature
	signedUserdataBytes, err := json.Marshal(signedUserdata)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(userUUID, signedUserdataBytes)
	
	return nil
}
