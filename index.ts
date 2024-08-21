import {
    IdentityKeyStore,
    ProtocolAddress,
    SessionStore,
    signalEncrypt,
    signalDecrypt,
    CiphertextMessage,
    SignalMessage,
    PublicKey,
    SessionRecord,
    PrivateKey, IdentityKeyPair, SignedPreKeyRecord, PreKeyBundle,
    processPreKeyBundle, PreKeyRecord, PreKeySignalMessage, CiphertextMessageType
} from '@signalapp/libsignal-client';

// Corrected createPreKeyBundle function
async function createPreKeyBundle(
    registrationId: number,
    deviceId: number,
    identityKeyPair: IdentityKeyPair,
    signedPreKey: SignedPreKeyRecord,
    preKeyId: number
): Promise<PreKeyBundle> {
    const preKeyPair = PreKeyRecord.new(preKeyId, identityKeyPair.publicKey, identityKeyPair.privateKey);

    return PreKeyBundle.new(
        registrationId,
        deviceId,
        preKeyId,
        preKeyPair.publicKey(),
        signedPreKey.id(),
        signedPreKey.publicKey(),
        signedPreKey.signature(),
        identityKeyPair.publicKey
    );
}

// Generate the required keys and create a PreKeyBundle for each member
async function generatePreKeyBundleForMember(
    memberId: string,
    registrationId: number,
    signedPreKeyId: number,
    identityStore: InMemoryIdentityKeyStore
): Promise<[PreKeyBundle, IdentityKeyPair]> {
    const identityKeyPair = IdentityKeyPair.generate();

    const signedPreKey = SignedPreKeyRecord.new(
        signedPreKeyId,
        new Date().getTime(),
        identityKeyPair.publicKey,
        identityKeyPair.privateKey,
        identityKeyPair.privateKey.sign(identityKeyPair.publicKey.serialize())
    );

    const preKeyId = registrationId;
    await identityStore.storeIdentityKeyPair(identityKeyPair);
    await identityStore.saveIdentity(ProtocolAddress.new(memberId, 1), identityKeyPair.publicKey);
    const preKeyBundle = await createPreKeyBundle(registrationId, 1, identityKeyPair, signedPreKey, preKeyId);

    return [preKeyBundle, identityKeyPair];
}

// In-memory stores for session and identity keys
class InMemorySessionStore extends SessionStore {
    private sessions: Map<string, SessionRecord> = new Map();

    async saveSession(name: ProtocolAddress, record: SessionRecord): Promise<void> {
        this.sessions.set(name.toString(), record);
    }

    async getSession(name: ProtocolAddress): Promise<SessionRecord | undefined> {
        return this.sessions.get(name.toString());
    }

    async containsSession(name: ProtocolAddress): Promise<boolean> {
        return this.sessions.has(name.toString());
    }
}

class InMemoryIdentityKeyStore extends IdentityKeyStore {
    getLocalRegistrationId(): Promise<number> {
        if(this.user === 'alice') {
            return Promise.resolve(1);
        }
        return Promise.resolve(2);
    }
    private identityKeys: Map<string, IdentityKeyPair> = new Map();
    private remoteIdentityKeys: Map<string, PublicKey> = new Map();
    public user: string;

    async storeIdentityKeyPair(identityKeyPair: IdentityKeyPair) {
        this.identityKeys.set('local', identityKeyPair);
    }

    async getIdentityKeyPair(): Promise<IdentityKeyPair> {
        const keyPair = this.identityKeys.get('local');
        if (!keyPair) {
            throw new Error('Local identity key pair not found');
        }
        return keyPair;
    }

    async getIdentityKey(): Promise<PrivateKey> {
        const keyPair = await this.getIdentityKeyPair();
        return keyPair.privateKey;
    }

    async saveIdentity(name: ProtocolAddress, identityKey: PublicKey): Promise<boolean> {
        this.remoteIdentityKeys.set(name.toString(), identityKey);
        return true;
    }

    async getIdentity(address: ProtocolAddress): Promise<PublicKey | undefined> {
        return this.remoteIdentityKeys.get(address.toString());
    }

    async isTrustedIdentity(name: ProtocolAddress, key: PublicKey, direction: number): Promise<boolean> {
        return true; // Simplified for this implementation
    }
}

const sessionStore = new InMemorySessionStore();

async function establishSession(
    senderId: string,
    receiverId: string,
    preKeyBundle: PreKeyBundle,
    receiverIdentityStore: InMemoryIdentityKeyStore
): Promise<void> {
    const address = ProtocolAddress.new(receiverId, 1);

    try {
        await processPreKeyBundle(preKeyBundle, address, sessionStore, receiverIdentityStore, new Date());
        console.log(`Session established between ${senderId} and ${receiverId}`);

        const sessionRecord = await sessionStore.getSession(address);
        if (!sessionRecord) {
            throw new Error(`Failed to store session between ${senderId} and ${receiverId}`);
        }
    } catch (error) {
        console.error('Error establishing session:', error);
    }
}

async function sendGroupMessage(
    senderId: string,
    groupMembers: string[],
    message: string,
    sessionStore: SessionStore,
    identityStore: IdentityKeyStore
): Promise<Map<string, CiphertextMessage>> {
    const encryptedMessages = new Map<string, CiphertextMessage>();

    for (const memberId of groupMembers) {
        if (memberId !== senderId) {
            const address = ProtocolAddress.new(memberId, 1);


                const encryptedMessage = await signalEncrypt(
                    Buffer.from(message, 'utf-8'),
                    address,
                    sessionStore,
                    identityStore,
                    new Date()
                );
                encryptedMessages.set(memberId, encryptedMessage);

        }
    }

    return encryptedMessages;
}

async function receiveGroupMessage(
    receiverId: string,
    senderId: string,
    encryptedMessage: CiphertextMessage,
    sessionStore: SessionStore,
    identityStore: IdentityKeyStore
): Promise<string> {
    const address = ProtocolAddress.new(senderId, 1);

    const messageType = encryptedMessage.type();
    switch (messageType) {
        case CiphertextMessageType.Whisper: {
            const signalMessage = SignalMessage.deserialize(encryptedMessage.serialize());
            const decryptedContent = await signalDecrypt(
                signalMessage,
                address,
                sessionStore,
                identityStore
            );
            return decryptedContent.toString('utf-8');
        }
        case CiphertextMessageType.PreKey: {
            console.error("Unexpected PreKeySignalMessage received. The session might not have been established correctly.");
            return "Error: PreKeySignalMessage received instead of SignalMessage.";
        }
        default:
            throw new Error(`Unsupported message type: ${messageType}`);
    }
}

(async function main() {
    const groupMembers = ['alice', 'bob'];
    const senderId = 'alice';

    const preKeyBundles = new Map<string, PreKeyBundle>();
    const identityStores = new Map<string, InMemoryIdentityKeyStore>();

    // Initialize PreKeyBundles and Identity Stores for each member
    for (const memberId of groupMembers) {
        const identityStore = new InMemoryIdentityKeyStore();
        identityStore.user = memberId;
        const [preKeyBundle] = await generatePreKeyBundleForMember(memberId, 1, 1, identityStore);
        preKeyBundles.set(memberId, preKeyBundle);
        identityStores.set(memberId, identityStore);
    }

    // Establish sessions between members before sending messages
    for (const memberId of groupMembers) {
        if (memberId !== senderId) {
            console.log(`Establishing session between ${senderId} and ${memberId}`);
            await establishSession(senderId, memberId, preKeyBundles.get(memberId), identityStores.get(memberId));
        }
    }

    const message = "Hello, Signal Group!";
    const encryptedMessages = await sendGroupMessage(senderId, groupMembers, message, sessionStore, identityStores.get(senderId)!);

    for (const [receiverId, encryptedMessage] of encryptedMessages) {
        const decryptedMessage = await receiveGroupMessage(receiverId, senderId, encryptedMessage, sessionStore, identityStores.get(receiverId)!);
        console.log(`Decrypted message for ${receiverId}:`, decryptedMessage);
    }
})();
