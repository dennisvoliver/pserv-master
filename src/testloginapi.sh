
# change this as per instruction to avoid conflicts.
PORT=10001

# to test against a working implementation (and see the intended responses)
# change this URL=http://theta.cs.vt.edu:3000/
URL=http://localhost:${PORT}

COOKIEJAR=cookies.txt


# clear cookies
/bin/rm ${COOKIEJAR}

# test authentication
curl -v -H "Content-Type: application/json" \
     -c ${COOKIEJAR} \
     -X POST \
     -d '{"username":"user0","password":"thepassword"}' \
    ${URL}/api/login

# this should succeed if the password is correct
curl -v \
    -b ${COOKIEJAR} \
    ${URL}/api/login

# create a 'private' folder first.
# this should fail since credentials were not presented
curl -v \
    ${URL}/private/secret.txt

# this should succeed since credentials were presented
curl -v \
    -b ${COOKIEJAR} \
    ${URL}/private/secret.txt

