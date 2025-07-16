const express = require('express');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
var Cookies = require('cookies');
dotenv.config();

const secretKey = process.env.JWT_SECRET || 'defaultSecretKey';
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true })); // To parse URL-encoded bodies

// use Pug as the view engine
app.set('view engine', 'pug');
app.set('views', './views'); // Set the views directory


const PORT = process.env.PORT || 3000;

const USERNAME = process.env.USERNAME || 'admin';
const PASSWORD = process.env.PASSWORD || 'password';
const IP_POWER_IP = process.env.IP_POWER_IP;

// Middleware to verify JWT
function verifyToken(req, res, next) {
    // Check for token cookie
    var cookies = new Cookies(req, res);
    const token = cookies.get('token');
    if (!token) {
        console.log('No token provided');
        return res.redirect('/login'); // Redirect to login if no token is provided
    }
    console.log('Token found:', token);
    // Extract the token string from the header
    if (Array.isArray(token)) {
        return res.status(400).send('Invalid Token Format');
    }

    //const tokenString = token.split(' ')[1]; // Assuming Bearer token format

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            console.error('Token verification failed:', err);
            return res.status(400).redirect('/login');

        }
        req.user = decoded;
        console.log("Token verification succeed")
        next();
    });
}

function parseStatus(text) {
    console.log("Result text:", text)
    var status = [null, null, null, null];
    var p1Pos = text.search(/p61=/);
    status[0] = parseInt(text[p1Pos + 4])
    var p2Pos = text.search(/p62=/);
    status[1] = parseInt(text[p2Pos + 4])
    var p3Pos = text.search(/p63=/);
    status[2] = parseInt(text[p3Pos + 4])
    var p4Pos = text.search(/p64=/);
    status[3] = parseInt(text[p4Pos + 4])
    return JSON.stringify(status);
}

function parseCycleStatus(text) {
    console.log("Result text:", text)
    var status = [null, null, null, null];
    var p1Pos = text.search(/p61/);
    if (p1Pos >= 0) {
        status[0] = text.slice(p1Pos+4, p1Pos + 12) == "cycle ok"
    }
    var p2Pos = text.search(/p62/);
        if (p2Pos >= 0) {
        status[1] = text.slice(p2Pos+4, p2Pos + 12) == "cycle ok"
    }
    var p3Pos = text.search(/p63/);
    if (p3Pos >= 0) {
        status[2] = text.slice(p3Pos+4, p3Pos + 12) == "cycle ok"
    }
    var p4Pos = text.search(/p64/);
    if (p4Pos >= 0) {
        status[3] = text.slice(p4Pos+4, p4Pos + 12) == "cycle ok"
    }

    console.log("Slice:", text.slice(p4Pos+4, p4Pos + 12));
    return JSON.stringify(status);
}

async function getPower() {
    const user = process.env.IP_POWER_USER || 'admin';
    const pw = process.env.IP_POWER_PW;

    const url = `http://${IP_POWER_IP}/set.cmd?cmd=getpower`;
    const headers = new Headers({
        'Authorization': `Basic ${btoa(user + ':' + pw)}`
    })
    console.log("Url:", url)
    const result = await fetch(url, { headers: headers })
        .catch((err) => {
            console.error("Error getting status:")
            console.error(err);
        });
    console.log("Result:")
    console.log(result);

    
    if (result?.ok) {
        var text = await result.text();
        return parseStatus(text);
    }


    return false;
}

async function setPowerCycle({ p1, p2, p3, p4 }) {
    paramString = "";
    if (p1 !== undefined && (p1 >= 0)) {
        paramString += "&p61=" + p1;
    }
    if (p2 !== undefined && (p2 >= 0)) {
        paramString += "&p62=" + p2;
    }
    if (p3 !== undefined && (p3 >= 0)) {
        paramString += "&p63=" + p3;
    }
    if (p4 !== undefined && (p4 >= 0)) {
        paramString += "&p64=" + p4;
    }
    console.log("ParamString", paramString);
    if (paramString.length == 0) {
        console.error("No param string");
        return null;
    }
    const user = process.env.IP_POWER_USER || 'admin';
    const pw = process.env.IP_POWER_PW;
    const url = `http://${IP_POWER_IP}/set.cmd?cmd=setpowercycle${paramString}`;
    const headers = new Headers({
        'Authorization': `Basic ${btoa(user + ':' + pw)}`
    })
    console.log("Url:", url)
    const result = await fetch(url, { headers: headers })
        .catch((err) => {
            console.error("Error getting status:")
            console.error(err);
        });
    console.log("Result:")
    console.log(result);

    var status = [null, null, null, null];
    if (result?.ok) {
        var text = await result.text();
        return parseCycleStatus(text);
    }


    return false;
}

async function setPower({ p1, p2, p3, p4 }) {
    console.log({p1, p2, p3, p4})
    paramString = "";
    if (p1 !== undefined && (p1 == 0 || p1 == 1)) {
        paramString += "&p61=" + p1;
    }
    if (p2 !== undefined && (p2 == 0 || p2 == 1)) {
        paramString += "&p62=" + p2;
    }
    if (p3 !== undefined && (p3 == 0 || p3 == 1)) {
        paramString += "&p63=" + p3;
    }
    if (p4 !== undefined && (p4 == 0 || p4 == 1)) {
        paramString += "&p64=" + p4;
    }
    console.log("ParamString", paramString);
    if (paramString.length == 0) {
        console.error("No param string");
        return null;
    }
    const user = process.env.IP_POWER_USER || 'admin';
    const pw = process.env.IP_POWER_PW;
    const url = `http://${IP_POWER_IP}/set.cmd?cmd=setpower${paramString}`;
    const headers = new Headers({
        'Authorization': `Basic ${btoa(user + ':' + pw)}`
    })
    console.log("Url:", url)
    const result = await fetch(url, { headers: headers })
        .catch((err) => {
            console.error("Error getting status:")
            console.error(err);
        });
    console.log("Result:")
    console.log(result);


    if (result?.ok) {
        var text = await result.text();
        return parseStatus(text);
    }


    return false;
}




// Route to generate JWT
app.post('/login', (req, res) => {

    var cookies = new Cookies(req, res);
    console.log(req);
    console.log('Login attempt:', req.body);
    const { username, password } = req.body;
    if (username === USERNAME && password === PASSWORD) {
        const token = jwt.sign({ username }, secretKey, { expiresIn: '1h' });
        console.log('Token generated:', token);
        // Set the token in a cookie
        cookies.set('token', token, {
            httpOnly: true, // Prevents client-side JavaScript from accessing the cookie
            secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
            maxAge: 3600000 // 1 hour
        });
        return res.redirect('/'); // Redirect to the home page after successful login
    }
    return res.status(401).send('Invalid Credentials');
});

app.get('/logout', (req, res) => {
    var cookies = new Cookies(req, res);
    cookies.set('token', { maxAge: 0 });
    return res.redirect('/login');
})

app.get('/login', (req, res) => {
    res.render('login', { title: 'Login' });
});

app.get('/', verifyToken, (req, res) => {
    res.render('dashboard', { title: 'Home', user: req.user });
});


app.get('/status', verifyToken, (req, res) => {
    getPower().then(result => {
        res.send(result);
    });
});


app.get('/set', verifyToken, async (req, res) => {
    console.log(req.query);
    const newStatus = await setPower(req.query);
    console.log("Sending status:", newStatus);
    res.status(200).send(newStatus);
})

app.get('/cycle', verifyToken, async (req, res) => {
    console.log(req.query);
    const newStatus = await setPowerCycle(req.query);
    console.log("Sending status:", newStatus);
    res.status(200).send(newStatus);
})

//redirect if user is not logged in
app.use((req, res, next) => {

    if (req.path === '/login') {
        return next(); // Allow login route to be accessed without token
    }
    if (!req.user) {
        //redirect to login page or send an error response
        //return res.status(401).send('Unauthorized');
        // Alternatively, you can redirect to a login page
        return res.redirect('/login');
        //return res.status(401).send('Unauthorized');
    }
    next();
});






app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

