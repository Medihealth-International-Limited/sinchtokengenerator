const express = require('express')
const atob = require('atob')
const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const { v4: uuid4 } = require('uuid')

const app = express()
const port = 6000
app.use(express.json())

function padString(number) {
  if (number < 10) {
    return `0${number}`
  }
  return `${number}`
}

function getToken(applicationsecret, applicationkey, userid) {
    const shasum = crypto.createHash('sha1');

    const sequence = 0;

    const stringToSign = userid + applicationkey + sequence + applicationsecret;

    shasum.update(stringToSign);

    const singnature = shasum.digest();
    console.log('Signature ', singnature.toString('base64'));
    const token = singnature.toString('base64').trim();

    console.log(token);
    return token
}

function signToken(applicationsecret, applicationkey, userid) {
  const newDate = new Date()
  const expDate = new Date()
  expDate.setMinutes(newDate.getMinutes() + 10)
  const payload = {
      "iss": `//rtc.sinch.com/applications/${applicationkey}`,
      "sub": `//rtc.sinch.com/applications/${applicationkey}/users/${userid}`,
      "iat": newDate.getTime(),
      "exp": expDate.getTime(),
      "nonce": uuid4()
  }

  const header = {
    "alg": "HS256",
    "kid": `hkdfv1-${newDate.getFullYear()}${padString(newDate.getMonth())}${padString(newDate.getDate())}`
  }

  let signingKey = crypto.createHmac('sha256', `${newDate.getFullYear()}${padString(newDate.getMonth())}${padString(newDate.getDate())}`).update(atob(applicationsecret)).digest("base64");
  console.log(typeof(crypto.subtle))
  // const signingKey = getToken(applicationsecret, applicationkey, userid)
  console.log("Signing Key:",signingKey)

  const token = jwt.sign(payload, signingKey, { header: header })
  console.log("JWT:",token)
  return token
}

app.post('/token', (req, res) => {
  const {applicationsecret, applicationkey, userid} = req.body
  const token = signToken(applicationsecret, applicationkey, userid)
  res.json({
    status: 'success',
    token,
  })
})

app.listen(port, () => {
  console.log(`Server is running on port ${port}`)
})
