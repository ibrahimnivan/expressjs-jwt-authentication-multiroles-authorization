# ---------------- JWT AUTH
## 1. INTRO
1. 1. When user complete their login process(authenticated), restAPI will issue the client application an "access token" and "refresh token"
    - Access Token = is given short time before expires (5 to 15 minutes)
        1. Access token adalah token keamanan yang digunakan untuk memberikan akses ke sumber daya yang dilindungi Token ini biasanya memiliki waktu aktif yang terbatas dan digunakan untuk mengotentikasi pengguna ke server atau layanan tertentu.
        2. Setelah access token kedaluwarsa, pengguna harus mendapatkan token baru dengan menggunakan refresh token atau melalui proses otentikasi ulang.
    - Refresh Token = is given a longer duration before expires (several hour or even days!)
        1. Refresh token adalah token yang digunakan untuk mendapatkan access token baru tanpa memerlukan otentikasi pengguna lagi.
        2. Biasanya, refresh token memiliki waktu aktif yang lebih lama dibandingkan access token.

our api will send and receive access tokens as json data, to prevent the risk of XXS and CSRF it's recommended to Frontend application to only store access tokens in memory so they will be automatically lost when app is closed, `shouldn't be stored in local storage or in a cookie!`

just keep access token in memory which you might also refer to as the current application state, our api will issue refrest token in an `http only cookie - this type cookie is not accessible with javascript`,refresh token do need to have expiration which will then which will then require users to login again

the overAll access token process involvees issuing(penerbitan) an access token during user authorization the user's applicationc can then access our rest api's protected route with access token until it expires, our api will verify access token with middleware everytime the access token is used to make a request, when the access token does expire the user's application will need to send their refresh token to our api's refresh endpoint to get a new access token of course the refresh token is also issued during user authorization

issued at authorization client uses to request new access Token verified with endpoint & database must be allowed to expire or logout


## 2. GETTING STARTED
- Install dotenv, jsonwebtoken, cookie-parser


## 3. GET A RANDOM CRYPTO BYTES FROM NODE CRYPTO
- in terminal, write node ENTER

    require('crypto').randomBytes(64).toString('hex')
    'be01924d6480a0b36d3463b7398655f0969de30e5af5d724cbc34bd4f44e8cbf8365a3be7e56d6644e85cdb7f96377b4ad5725eeafe5097dcf51fd962bb23652'

## 4. CREATE .ENV FILE AND ITS VARIABLE

    ACCESS_TOKEN_SECRET=be01924d6480a0b36d3463b7398655f0969de30e5af5d724cbc34bd4f44e8cbf8365a3be7e56d6644e85cdb7f96377b4ad5725eeafe5097dcf51fd962bb23652

    REFRESH_TOKEN_SECRET=f439de666238b5ab94f934c17f6336f40eadb43932a91b35278c2046f366adfb5375ae54a1b8fdd9384c805a1d96a9453f0e15d08443bab3017553a7533fda81

## 5. IN authController.js ENCODED DATA WITH JWT
    const usersDB = {
        users: require('../model/users.json'),
        setUsers: function (data) { this.users = data }
    }
    const bcrypt = require('bcrypt');
```js
    const jwt = require('jsonwebtoken');
    require('dotenv').config()
    const fsPromises = require('fs').promises
    const path = require('path');
```
    const handleLogin = async (req, res) => {
        const { user, pwd } = req.body;
        if (!user || !pwd) return res.status(400).json({ 'message': 'Username and password are required.' });
        const foundUser = usersDB.users.find(person => person.username === user);
        if (!foundUser) return res.sendStatus(401); //Unauthorized 
        // evaluate password 
        const match = await bcrypt.compare(pwd, foundUser.password);
        if (match) {
```js
            // create JWTs
            const accessToken = jwt.sign({
                "username": foundUser.username
            }, process.env.ACCESS_TOKEN_SECRET, { expiration: '30s'})

            const refreshToken = jwt.sign({
                "username": foundUser.username
            }, process.env.REFRESH_TOKEN_SECRET, { expiration: '1d'})

             await fsPromises.writeFile(
            path.join(__dirname, '..', 'model', 'users.json'),
            JSON.stringify(usersDB.users)
        )
                // httpOnly is important
        res.cookie('jwt', refreshToken, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 })
        res.json({ accessToken });
```  
        } else {
            res.sendStatus(401);
        }
    }

    module.exports = { handleLogin };

## 5. CREATE verifyJWT.js in Middlewarer
```js
    const jwt = require('jsonwebtoken');
    require('dotenv').config();

    const verifyJWT = (req, res, next) => {
        const authHeader = req.headers['authorization'];
        
        if (!authHeader) return res.sendStatus(401);
        console.log(authHeader); // Bearer token
        const token = authHeader.split(' ')[1];
        jwt.verify(
            token,
            process.env.ACCESS_TOKEN_SECRET,
            (err, decoded) => {
                if (err) return res.sendStatus(403); //invalid token
                req.user = decoded.username;
                next();
            }
        );
    }

    module.exports = verifyJWT
```




## 7. APPLIED IT TO server.js
      app.use('/', require('./routes/root'));
      app.use('/register', require('./routes/register'));
      app.use('/auth', require('./routes/auth'));

      app.use(verifyJWT);                                          <<<<<
      app.use('/employees', require('./routes/api/employees'));

## 8. INITIALIZE MIDDLEWARE FOR COOKIE IN server.js
    const cookieParser = require('cookie-parser');                <<<<<

    // custom middleware logger
    app.use(logger);

    // Cross Origin Resource Sharing
    app.use(cors(corsOptions));

    // built-in middleware to handle urlencoded form data
    app.use(express.urlencoded({ extended: false }));

    // built-in middleware for json 
    app.use(express.json());
```js
    // middleware for cookie
    app.use(cookieParser())
```
    //serve static files
    app.use('/', express.static(path.join(__dirname, '/public')));

## 9. CREATE refreshTokenController.js
```js
    const usersDB = {
        users: require('../model/users.json'),
        setUsers: function (data) { this.users = data }
    }
    const jwt = require('jsonwebtoken');
    require('dotenv').config();

    const handleRefreshToken = (req, res) => {
        const cookies = req.cookies;
        if (!cookies?.jwt) return res.sendStatus(401); // refresh token
        const refreshToken = cookies.jwt;

        const foundUser = usersDB.users.find(person => person.refreshToken === refreshToken);
        if (!foundUser) return res.sendStatus(403); //Forbidden 
        // evaluate jwt 
        jwt.verify(
            refreshToken,
            process.env.REFRESH_TOKEN_SECRET,
            (err, decoded) => {
                if (err || foundUser.username !== decoded.username) return res.sendStatus(403); // validation
                const accessToken = jwt.sign( // generate new acces token
                    { "username": decoded.username }, // from refresh token
                    process.env.ACCESS_TOKEN_SECRET,
                    { expiresIn: '30s' }
                );
                res.json({ accessToken })
            }
        );
    }

    module.exports = { handleRefreshToken }
```

## 10. CREATE routes > refresh.js
```js
    const express = require('express');
    const router = express.Router();
    const refreshTokenController = require('../controllers/refreshTokenController');

    router.get('/', refreshTokenController.handleRefreshToken);

    module.exports = router;
```

## 11. IN Server.js
    app.use('/', require('./routes/root'));
    app.use('/register', require('./routes/register'));
    app.use('/auth', require('./routes/auth'));
    app.use('/refresh', require('./routes/refresh'));                        <<<<<

    app.use(verifyJWT);                                        
    app.use('/employees', require('./routes/api/employees'));

EXPLANATION : everytime we sent request to /resfresh new access token is generated


## 12. ADD logoutController.ts
```js
const usersDB = {
  users: require('../model/users.json'),
  setUsers: function (data) { this.users = data }
}
    const fsPromises = require('fs').promises;
    const path = require('path');

    const handleLogout = async (req, res) => {
      // On client, also delete the accessToken

      const cookies = req.cookies;
      if (!cookies?.jwt) return res.sendStatus(204); //No content
      const refreshToken = cookies.jwt;

      // Is refreshToken in db?
      const foundUser = usersDB.users.find(person => person.refreshToken === refreshToken);
      if (!foundUser) {
        // if we dont have foundUser but we did have  to get to this  point we can just erase the cookie
          res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });
          return res.sendStatus(204);
      }

      // Delete refreshToken in db
      const otherUsers = usersDB.users.filter(person => person.refreshToken !== foundUser.refreshToken);
      const currentUser = { ...foundUser, refreshToken: '' };
      usersDB.setUsers([...otherUsers, currentUser]);
      await fsPromises.writeFile(
          path.join(__dirname, '..', 'model', 'users.json'),
          JSON.stringify(usersDB.users)
      );

      res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });
      res.sendStatus(204);
    }

    module.exports = { handleLogout }
```


## 13. CREATE routes > logout.js
```js
        const express = require('express');
        const router = express.Router();
        const logoutController = require('../controllers/logoutController');

        router.get('/', logoutController.handleLogout);

        module.exports = router;
```
13. 1.  IN server.js ADD
app.use('/logout', require('./routes/logout'));

## 14. IN FRONTEND
```js

        const sendLogin = async () => {
            const user = document.getElementById("user").value;
            const pwd =  document.getElementById("pwd").value;
            try {
            const response = await fetch('http://localhost:3500/auth', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'}, 
                credentials: 'include',
                body: JSON.stringify({ user, pwd })
            });
                if (!response.ok) {
                    if (response.status === 401) {
                    return await sendRefreshToken();
                }
                throw new Error(`${response.status} ${response.statusText}`)
            }
            return await response.json();
        } catch (err) {
            console.log(err.stack);
            displayErr();
        }
}
```
## 15. CREATE middleware > credentials.js
- Kredensial dalam konteks CORS merujuk pada penggunaan cookie header otentikasi HTTP
-  Jika Anda ingin menyertakan kredensial (seperti cookie atau token otentikasi) dalam permintaan lintas asal, Anda perlu menetapkan properti credentials ke nilai 'include'

```js
        const allowedOrigins = require('../config/allowedOrigins');

        const credentials = (req, res, next) => {
            const origin = req.headers.origin;
            if (allowedOrigins.includes(origin)) {
                res.header('Access-Control-Allow-Credentials', true);
            }
            next();
        }

        module.exports = credentials
```
# -------------  USER ROLES
## 1. CREATE config > roles_list.js
```js
    const ROLES_LIST = {
        "Admin": 5150, // code to identify the role
        "Editor": 1984,
        "User": 2001
    }

    module.exports = ROLES_LIST
```




## 2. MODIFY users model (model > users.js)
```js
    [
    {
        "username": "dave1",
        "roles": { "User": 2001 },
        "password": "$2b$10$oEbHZlazDHE1YnnJ4XdpGuGh9a/JZOO7Xe6WZtRRsSMgprxMXnKza",
        "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImRhdmUxIiwiaWF0IjoxNjMzOTkyMjkwLCJleHAiOjE2MzQwNzg2OTB9.U85HVX_gcDZkHHSRWeo7AHfIe7q9i03dGW2ed3fHqAk"
    },
    {
        "username": "walt2",
        "roles": { "User": 2001, "Editor": 1984 },
        "password": "$2b$10$cvfmz./teMWDccIMChAxZ.HqgL3eoQGYTm1z9lGy5iRf8D7NNargC",
        "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IndhbHQyIiwiaWF0IjoxNjMzOTkyNDU2LCJleHAiOjE2MzQwNzg4NTZ9.wRVJbN7_67JyTW9PALMWWEsO4BMkehyy5kXq6WilvWc"
    },
    {
        "username": "walt1",
        "roles": { "User": 2001, "Editor": 1984, "Admin": 5150 },
        "password": "$2b$10$33Q9jtAoaXC4aUX9Bjihxum2BHG.ENB6JyoCvPjnuXpITtUd8x8/y",
        "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IndhbHQxIiwiaWF0IjoxNjMzOTkyNTY0LCJleHAiOjE2MzQwNzg5NjR9.gE2CgbtEuqE42LeJ4dP6APmqyGTNBh53WXVyDdP47yM"
    }
    ]

```

## 3. ADD ROLES IN registerController.js
```js
        const newUser = { 
            "username": user, 
            "roles": { "user": 2001 },
            "password": hashedPwd 
        };
```
## 4. CHANGE ACCESS TOKEN PAYLOAD IN authController.js
- no reason to send roles in refresh token, access token will only be stored in memory frontend

    const match = await bcrypt.compare(pwd, foundUser.password);
    if (match) {
        const roles = Object.values(foundUser.roles);     <<<  
        // create JWTs
```js
        const accessToken = jwt.sign({
            "UserInfo": {
                "username": foundUser.username,
                "roles": roles
            }
```
        }, process.env.ACCESS_TOKEN_SECRET, { expiration: '30s'})

        const refreshToken = jwt.sign({
            "username": foundUser.username
        }, process.env.REFRESH_TOKEN_SECRET, { expiration: '1d'})

        // savig refresh token with currentUser
        const otherUsers = usersDB.users.filter(person => person.username !== foundUser.username);
        const currentUser = { ...foundUser, refreshToken}
        usersDB.setUsers([...foundUser, currentUser])
        await fsPromises.writeFile(
            path.join(__dirname, '..', 'model', 'users.json'),
            JSON.stringify(usersDB.users)
        )
                                       // httpOnly is important
        res.cookie('jwt', refreshToken, { httpOnly: true, sameSite: 'None', secure: true, maxAge: 24 * 60 * 60 * 1000 });
        res.json({ accessToken });
    }

## 5. MODIFY refreshTokenController.js
 jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET,
      (err, decoded) => {
          if (err || foundUser.username !== decoded.username) return res.sendStatus(403);
```js
          const roles = Object.values(foundUser.roles);
            const accessToken = jwt.sign(
                {
                    "UserInfo": {
                        "username": decoded.username,
                        "roles": roles
                    }
                },
```
                process.env.ACCESS_TOKEN_SECRET,
                { expiresIn: '30s' }
            );
          res.json({ accessToken })
      }
  );
## 6. MODIFY middleware > veryfyJWT.js

    const jwt = require('jsonwebtoken');
    require('dotenv').config();

    const verifyJWT = (req, res, next) => {
        const authHeader = req.headers.authorization || req.headers.Authorization; // just in case we it's A or a
        if (!authHeader?.startsWith('Bearer ')) return res.sendStatus(401);

        const token = authHeader.split(' ')[1];
        jwt.verify(
            token,
            process.env.ACCESS_TOKEN_SECRET,
```js
            (err, decoded) => {
                if (err) return res.sendStatus(403); //invalid token
                req.user = decoded.UserInfo.username;
                req.roles = decoded.UserInfo.roles;
                next();
            }
```
        );
    }

    module.exports = verifyJWT

## 7. CREATE middleware > veryfyRoles.js
```js
    const verifyRoles = (...allowedRoles) => {
        return (req, res, next) => {
            if (!req?.roles) return res.sendStatus(401);
            const rolesArray = [...allowedRoles];
            const result = req.roles.map(role => rolesArray.includes(role)).find(val => val === true);
            if (!result) return res.sendStatus(401);
            next();
        }
    }

    module.exports = verifyRoles
```
## 8. MODIFY routes > api > employees.js

    const express = require('express');
    const router = express.Router();
    const employeesController = require('../../controllers/employeesController');
```js
    const ROLES_LIST = require('../../config/roles_list');
    const verifyRoles = require('../../middleware/verifyRoles');

    router.route('/')
        .get(employeesController.getAllEmployees) // every role can access
        .post(verifyRoles(ROLES_LIST.Admin, ROLES_LIST.Editor), employeesController.createNewEmployee) // only admin and editor
        .put(verifyRoles(ROLES_LIST.Admin, ROLES_LIST.Editor), employeesController.updateEmployee)
        .delete(verifyRoles(ROLES_LIST.Admin), employeesController.deleteEmployee); // only admin
```
    router.route('/:id')
        .get(employeesController.getEmployee);

    module.exports = router;

## 9. TESTING
- test 1
    POST localhost:3500/auth 
    body = dave1 => roles = user

    GET localhost:3500/employees  => can be access
    POST localhost:3500/employees  => unauhorized
- test 3 
    POST localhost:3500/auth 
    body = walt1 => roles = user, editor, admin

    GET localhost:3500/employees  => can be access
    POST localhost:3500/employees  => can be access
    DELETE localhost:3500/employess => can be access




##
