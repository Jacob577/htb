## The most common mistakes in applications:
    1. 	Permitting Invalid Data to Enter the Database
    2. 	Focusing on the System as a Whole
    3. 	Establishing Personally Developed Security Methods
    4. 	Treating Security to be Your Last Step
    5. 	Developing Plain Text Password Storage
    6. 	Creating Weak Passwords
    7. 	Storing Unencrypted Data in the Database
    8. 	Depending Excessively on the Client Side
    9. 	Being Too Optimistic
    10. 	Permitting Variables via the URL Path Name
    11. 	Trusting third-party code
    12. 	Hard-coding backdoor accounts
    13. 	Unverified SQL injections
    14. 	Remote file inclusions
    15. 	Insecure data handling
    16. 	Failing to encrypt data properly
    17. 	Not using a secure cryptographic system
    18. 	Ignoring layer 8
    19. 	Review user actions
    20. 	Web Application Firewall misconfigurations

## OWASP 10
    1. 	Injection
    2. 	Broken Authentication
    3. 	Sensitive Data Exposure
    4. 	XML External Entities (XXE)
    5. 	Broken Access Control
    6. 	Security Misconfiguration
    7. 	Cross-Site Scripting (XSS)
    8. 	Insecure Deserialization
    9. 	Using Components with Known Vulnerabilities
    10. 	Insufficient Logging & Monitoring

How can an html injection look like?
```html
><img src=/ onerror=alert(document.cookie)>

// or
"><script src=//www.example.com/exploit.js></script>
```

[OWASP cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

## Common web errors:

    Successful responses 	
    200 OK 	The request has succeeded
    201 Created
    Redirection messages 	
    301 Moved Permanently 	The URL of the requested resource has been changed permanently
    302 Found 	The URL of the requested resource has been changed temporarily
    Client error responses 	
    400 Bad Request 	The server could not understand the request due to invalid syntax
    401 Unauthorized 	Unauthenticated attempt to access page
    403 Forbidden 	The client does not have access rights to the content
    404 Not Found 	The server can not find the requested resource
    405 Method Not Allowed 	The request method is known by the server but has been disabled and cannot be used
    408 Request Timeout 	This response is sent on an idle connection by some servers, even without any previous request by the client
    Server error responses 	
    500 Internal Server Error 	The server has encountered a situation it doesn't know how to handle
    502 Bad Gateway 	The server, while working as a gateway to get a response needed to handle the request, received an invalid response
    504 Gateway Timeout 	The server is acting as a gateway and cannot get a response in time

Wht curl flag do you use to also get server responses? 
`-I`

How do you connect to a database using php?
```php
$conn = new mysqli("localhost", "user", "pass");

# Create
$sql = "CREATE DATABASE database1";
$conn->query($sql)

# query
$conn = new mysqli("localhost", "user", "pass", "database1");
$query = "select * from table_1";
$result = $conn->query($query);

# Query
$searchInput =  $_POST['findUser'];
$query = "select * from users where name like '%$searchInput%'";
$result = $conn->query($query);

# response back:
while($row = $result->fetch_assoc() ){
	echo $row["name"]."<br>";
}

```

`SOAP` is commonly used to transfer structured data

What does `REST` stand for? `Representational State Transfer`

What pice can you add to url to get users?
`/index.php?id=0`

How can an sql injection look like using php?
```php
$query = "select * from users where name like '%$searchInput%'";
```


Where can you find a voulnerability library for wordpress?
[Here](https://www.rapid7.com/db/?q=wordpress&type=nexpose)

What is the severity rating for a voulerability called?
`CVSS V3.0 or V2.0`

