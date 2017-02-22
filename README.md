# Sample Burp Suite extension: Intruder payloads

This example shows how you can use an extension to:
- Generate custom Intruder payloads
- Apply custom processing to Intruder payloads (including built-in ones)

When an extension registers itself as an Intruder payload provider, this will
be available within the Intruder UI for the user to select as the payload
source for an attack. When an extension registers itself as a payload
processor, the user can create a payload processing rule and select the
extension's processor as the rule's action.

When Burp calls out to a payload provider to generate a payload, it passes the
base value of the payload position as a parameter. This allows you to create
attacks in which a whole block of serialized data is marked as the payload
position, and your extension places payloads into suitable locations within
that data, and re-serializes the data to create a valid request. Hence, you can
use Intruder's powerful attack engine to automatically manipulate input deep
within complex data structures.

This example is artificially simple, and generates two payloads: one to identify
basic XSS, and one to trigger the ficititious vulnerability that was used in the
[custom scanner checks
example](//github.com/PortSwigger/example-scanner-checks). It then uses a custom
payload processor to reconstruct the serialized data structure around the custom
payload.

This repository includes source code for Java, Python and Ruby. It also includes
a server (for ASP.NET and NodeJS) that extends the [serialization
example](//github.com/PortSwigger/example-custom-editor-tab) to add some
fictitious bugs so that you can test the custom payloads, and see that the two
vulnerabilities are triggered.

After loading the extension, you'll need to:
- Select "Extension-generated" payloads as your Intruder payloads type.
- Add a payload processing rule choosing the "Invoke Burp extension" processor.
- Start an attack against a POST sent to the included webserver.

Note: the sample server uses the JavaScript btoa() function to perform
Base64-encoding on the client side. This function is not supported by Internet
Explorer, but works on most other browsers.
