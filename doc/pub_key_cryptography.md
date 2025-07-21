# What is Public Key Cryptography?


The first thing I learned about the internet was email. I appreciate the convenience it brings, revolutionizing the way we communicate. Messages travel at lightning speed, reaching recipients in seconds, no matter where they are.

However, over time, some issues have arisen from the fundamental design of the email system, or more precisely the Internet, which originated from ARPANET, a project funded by the U.S. Department of Defense. Privacy and security were not primary concerns back then. Now, we face data breaches and phishing attacks, highlighting the lack of security in the email system.

This makes me nostalgic for traditional mail—the kind created with paper and pen. Letters are sealed in envelopes, ensuring they remain intact until they reach the recipient. Additionally, we can be certain that letters come from known senders because we recognize their familiar handwriting. What a simple and effective system!

Throughout history, humans have valued the integrity of important information. The Romans used the Caesar cipher, and the Germans used the Enigma machine during World War II. Although the Enigma machine was much more sophisticated than the Caesar cipher, the Allies managed to capture several of them and ultimately broke the code.

The problem with those methods was that they relied on a shared secret between the sender and the recipient. To share the secret, confidential information had to leave its safe enclave, exposing it to danger. Image that a lock has two keys, one stays with the creator, while another goes out for the others, such that losing the key in the open is not fatal any more.

Although we have not seen that kind of magic locks in the tangible world, some clever people devised a solution perfect for the digital universe. The conception of the two-key locks is that the receiver gives the sender a key to scramble the message before sending it and that the receiver then uses a different key to unscramble it. The sender can apply the key to the message only once, and if a third party tries to use the same key again, it would just create another jumble. Because the sender's key is useless for deciphering, it can be distributed widely without any concerns.

Building on this idea, three individuals with the initials RSA developed a scheme to implement this trapdoor function. For example, if Alice wants to send a message to Bob, Bob generates a pair of keys and sends one (a combination of 3 and 33) to Alice. Alice uses this key to encode her message, number 4. She calculates 4 to the power of 3, getting 64, then divides 64 by 33 to get the remainder, which is 31. Alice sends 31 to Bob. Bob then uses his secret key (7 and 33) to decode it. He calculates 31 to the power of 7, which is 27,512,614,111, then divides that large number by 33 to get the remainder, which is 4—the original message Alice sent.

If a villain intercepts Alice's combination of 3 and 33 and the number 31, they would calculate 31 to the power of 3 and divide it by 33, resulting in 25, which is not Alice's message.

This one-way operation has another application. For example, if Alice wants to send Bob a business document, number 4, she scrambles it with her secret key (3 and 55) first. She calculates 4 to the power of 3, getting 64, then divides 64 by 55 to get the remainder, 9. Alice sends 9 to Bob along with another pair of key, (27 and 55). Bob calculates 9 to the power of 27, getting 58,149,737,003,040,059,690,390,169, then divides that large number by 55 to get the remainder, 4—the original document. Only the pair of 3 and 55 can generate the number 9, so Bob can be sure the document is from Alice.

The key shared with other parties is called the public key, while the key kept secret is the private key. This approach, which offers both privacy and authenticity, is known as public key cryptography. RSA was a seismic revolution in cryptography when it was first proposed, however, the algorithm is becoming unpractical due to the progress in computing capacity. There are now new methods to achieve the same goal. 