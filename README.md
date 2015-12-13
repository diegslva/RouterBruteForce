# RouterBruteForce

Scan an IP address range for routers/modems implementing HTTP basic authentication that are exposed to the Internet. Attempt to login with a set of common default usernames and passwords. Eliminate false positives by verifying that the HTML source code of the router/modem contains either the word "router" or the word "modem".
