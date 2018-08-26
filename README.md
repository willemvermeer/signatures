# signatures
Source code to manually generate a Signature for your SAML 2.0 Response. It contains the code described in my blog post on http://wwwilpower.blogspot.com/2018/08/how-to-manually-generate-signature-for.html

## How to run

mvn clean install exec:java -Dexec.mainClass="com.example.OpenSamlSignatures"

This will execute the main class which loads an example SAML response, then proceeds to sign it using the OpenSAML libraries followed by signing it 'manually'.

The example generates a new private/public key pair upon each execution.

