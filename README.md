> **Introduction** **to** **Cryptography** **Group** **Homework**

**Group** **Members:**

> 1\. Azim TunaAğdaş - 2011051069
>
> 2\. Batuhan Berke Yıldırım - 2011051010 3. Timur Yaşar - 2011051057

**Division** **of** **Responsibilities**

The responsibilities for the project were divided among the group
members as follows:

> • **Azim** **Tuna** **Ağdaş**:
>
> Responsible for implementing authentication operations, securely
> hashing passwords, and storing them in a secure way within the system.
>
> • **Batuhan** **Berke** **Yıldırım**:
>
> Responsible for implementing the Diffie-Hellman key exchange protocol
> to establish a shared secret key and encrypting emails using theAES
> encryption algorithm.
>
> • **TimurYaşar**:
>
> Responsible for designing the digital signature mechanism for
> encrypted messages using the RSA algorithm, as well as generating RSA
> private and public key pairs.

**Project** **Overview**

In this project, we developed a secure email system consisting of one
server and one client application, designed to ensure user
authentication, message confidentiality, and integrity verification. The
development process utilized different tools and programming languages
for the server and client components, according to their specific
responsibilities:

> • **Server**:
>
> The server was implemented using Kotlin and Spring Boot. It
> communicates with a PostgreSQL database to manage user and email data.
> The server is responsible for:
>
> o Performing authentication operations (such as verifying user
> credentials).
>
> o Storing user passwords in hashed form.
>
> o Storing users' public keys securely.
>
> o Storing encrypted emails received from clients.
>
> • **Client**:
>
> The client application was developed using Python. It primarily
> handles cryptographic operations and ensures the security of private
> keys. The client is responsible for:
>
> o Creating private and public keys
>
> o Storing users' private keys.
>
> o Performing encryption and decryption operations for email messages.

This division allows the server to act as a centralized, secure storage
and authentication management system, while the client performs local
cryptographic operations to maintain end-to-end security.

**Authentication**

To ensure the password secrecy, we used Blowfish algorithm to hash
passwords. There is a built-in library in Spring Security named
BcryptPasswordEncoder which uses Blowfish algorithm. We stored the
hashed version of passwords in the database.

**Email** **Encryption** **and** **Digital** **Signature** **Mechanism**

To ensure the confidentiality and authenticity of email messages, we
implemented a combination of symmetric encryption (AES) and a digital
signature mechanism (RSA). Below is a detailed explanation of how these
mechanisms work in our system:

**Symmetric** **Encryption** **with** **AES**

For encrypting email messages, we used theAES-256 algorithm. The
encryption key is derived from the Diffie-Hellman key exchange, which
generates a shared secret key between two clients. However, since the
generated key from Diffie-Hellman is longer than 32 bytes (the required
length for AES-256), the key is adjusted using the SHA256 hashing
algorithm. This derived key is then used forAES encryption to secure the
email content. The encrypted message ensures the confidentiality of the
communication by preventing unauthorized access to the message content.

**Digital** **Signature** **forAuthenticity** **and** **Integrity**

To verify the sender's identity and ensure the integrity of the message,
a digital signature mechanism was implemented as follows:

> 1\. **Signing** **the** **Message**:
>
> o The encrypted message is first hashed using the SHA-256 algorithm to
> generate a unique hash value.
>
> o This hash value is then encrypted using the sender's RSA private
> key, creating the digital signature.
>
> o The digital signature is sent along with the encrypted message to
> the recipient.
>
> 2\. **Verifying** **the** **Message**:
>
> o Upon receiving the encrypted message and the digital signature, the
> recipient uses the sender's RSA public key to decrypt the digital
> signature, obtaining the original hash value.
>
> o The recipient then hashes the received encrypted message using
> SHA-256 to generate a new hash value.
>
> o The two hash values (decrypted from the signature and calculated
> from the message) are compared. If they match, the message is verified
> as authentic and unaltered.
>
> **3.** **Decrypting** **the** **Message**
>
> After verifying the message's authenticity, the recipient decrypts the
> message content as follows:
>
> • The Diffie-Hellman shared secret key is used to derive theAES key
> (using the same method as the sender).
>
> • TheAES key is then used to decrypt the encrypted message, revealing
> the original email content.
>
> This combination of AES encryption for message confidentiality and
> RSA-based digital signatures for authenticity and integrity ensures a
> secure and reliable email communication system.

**Step-by-Step** **Implementation**

**Scenario:** Alice and Bob register as users, after which Alice sends
an email to Bob, and Bob views the content of this email.

> **1.** **Step:** Alice and Bob register to the system
>
> <img src="./nbauh213.png" style="width:6.5in;height:2.35347in" />When
> registering, we also receive key exchange information for Diffie
> Hellman from the user, so before registration, the user must get the
> generator and prime number values from the server to create this
> information.
>
> After obtaining the Diffie Hellman parameters from the server, the
> client generates its own secret Diffie Hellman key. Using the
> parameters received from the server, the client computes its Diffie
> Hellman public key.
>
> Also, the client creates a pair of RSA public and private keys, which
> will be used for the digital signature mechanism. The client then
> sends the generated Diffie Hellman public key and RSA public key,
> along with the user information, to the server. The server hashes the
> password using SHA256 before storing it in the database to ensure
> secure storage of user credentials.

<img src="./dfh55uco.png"
style="width:6.21042in;height:2.98611in" />

> **2.** **Step:** Alice login to the system
>
> To log in, the user sends their email and password to the server. Upon
> successful authentication, the server responds with a JWT token. The
> user includes this token in the header of subsequent HTTP requests to
> authenticate their identity within the system. This secure token
> mechanism ensures that the user remains verified throughout their
> session.

<img src="./bgou20q0.png"
style="width:6.375in;height:3.13542in" />

> **3.** **Step:** Alice encrypts the message, creates signature and
> sends them to the server.
>
> To send an email, Alice must first enter Bob's email address. A
> request is made to the server to check if the entered email address is
> registered in the system. If the email is found in the database, the
> server responds with Bob's Diffie-Hellman public key. This public key
> will be used for securely encrypting the email content before it is
> sent to Bob.

<img src="./1epxpmmt.png" style="width:6.5in;height:2.63333in" />

> After receiving Bob's Diffie-Hellman public key and using her own
> Diffie-Hellman private key, Alice creates a shared secret key. This
> shared secret key is then hashed using SHA-256 to ensure it meets the
> 32-byte requirement for the AES-256 algorithm. With this hashed key,
> Alice encrypts the message she wishes to send using AES.
>
> <img src="./jxlh3sd4.png" style="width:6.5in;height:2.60972in" />However,
> while the message is encrypted for security, the authenticity of the
> sender must also be verified. To address this, a digital signature
> mechanism is implemented. Alice first hashes the encrypted message
> using SHA-256. Then, she encrypts this hash with her RSA private key,
> which was generated and stored during the registration process. Both
> the encrypted message and the digital signature are sent together to
> the server, ensuring that the recipient can verify the source of the
> message as well as its integrity.

<img src="./vvwgeskn.png" style="width:6.5in;height:2.92431in" />

> 4\. **Step:** Bob gets his mails from server, then verifies signatures
> and decrypts messages
>
> Bob sends a request to the server to retrieve the emails sent to him.
> In response, the server provides Bob with the emails as well as the
> public key information of the senders. Along with the email content,
> metadata such as the sender's identity and the date the email was sent
> is also included. With this information, Bob can proceed to verify the
> digital signatures of each email to ensure their authenticity before
> decrypting the messages.
>
> After receiving the email information, the client first performs the
> signature verification process. To do this, it uses the provided RSA
> public key of the sender to decrypt the received signature. Then, the
> client hashes the encrypted message using SHA-256 and compares this
> hash with the decrypted data. If they match, the signature is
> verified, confirming the authenticity of the email before proceeding
> to decrypt the message.
>
> After successfully verifying the signature, Bob needs to decrypt the
> message content. To do this, he utilizes the Diffie-Hellman public key
> of the sender along with his own Diffie-Hellman private key, as the
> sender used Bob's public key and their own private key to encrypt the
> message. Diffie-Hellman Key Exchange allows Bob to derive the shared
> secret key.
>
> Since the shared secret key's length does not meet the 32-byte
> requirement forAES-256, Bob hashes this key using SHA-256 to obtain a
> suitable AES key. With this key, he then performs the decryption using
> the AES-256 algorithm, allowing him to access the original message
> content.

<img src="./4cqjafuy.png" style="width:6.5in;height:2.73611in" />

**Screentshots**

Register and Login

<img src="./502r4lio.png" style="width:6.5in;height:1.94444in" />Passwords
are stored in hashed format in the db

<img src="./2zt2olv3.png" style="width:6.5in;height:2.1368in" />

Sending email

<img src="./psflg2vs.png"
style="width:7.12361in;height:2.12917in" />How emails are stored in the
database

<img src="./tlysuhpl.png"
style="width:6.11458in;height:3.71875in" />

Listing emails

**Code** **examples**

<img src="./xprmhund.png" style="width:6.5in;height:1.66736in" />generator
and prime parameters comes from the server

<img src="./12ofrdez.png"
style="width:5.9375in;height:3.40625in" /><img src="./dglyuuy3.png" style="width:6.5in;height:3.61667in" />

<img src="./y0rfgkhm.png"
style="width:6.50417in;height:3.6125in" /><img src="./ktpxy1pk.png" style="width:6.5in;height:5.69097in" />

<img src="./p50u3obn.png" style="width:6.5in;height:3.62986in" />

**Running** **steps**

> 1\. The project connects to a PostgreSQL database, so firstly we need
> to run an instance. A docker-compose file added to project folders,
> you can create this instance by using this docker-compose file.
>
> 2\. After the database instance created, the server needs to be
> started-up.Server port and database connection information are stored
> in configuration file of Spring Boot (application.yml).
>
> 3\. After all,we can run the client (client.py) to connect tothe
> server.
