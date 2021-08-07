var app = require("express")(),
    bcrypt = require('bcrypt'),
    jwt = require("jsonwebtoken"),
    configuration = require("./configuration.json"),
    { MongoClient, ObjectId } = require("mongodb");

// online users
const onlineUsers = [];
let requestId = 1;

app.use(require("express").json())
    .use(require('nocache')())
    .use(async (req, res, next) => {
        req.startTime = Date.now() / 1000.0;
        res.generatedBaseContent = {
            api: req.url.split("/")[2].split("?")[0],
            contents: [],
            error: null,
            timeStatus: {
                startTime: req.startTime
            },
            requestInfo: {
                ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
                url: req.url,
                requestId: requestId,
                authorization: null,
                generatedJWTtoken: null
            }
        }
        requestId += 1;
        next();
    })
    .set('etag', false);

// public functions of server

app.get("/public/server-time", async (req, res) => {
    res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
    res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;
    res.send(res.generatedBaseContent);
})

app.get("/public/catalog", async (req, res) => {
    MongoClient.connect(configuration.mongoDb.server, async (error, client) => {
        const collection = client.db(configuration.mongoDb.db).collection("content");

        res.generatedBaseContent.contents = await collection.find({ status: "VERIFIED_OK", public: true }).toArray();

        res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
        res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;

        res.send(res.generatedBaseContent);
        client.close();
    });
});

app.get("/public/stats", async (req, res) => {
    MongoClient.connect(configuration.mongoDb.server, async (error, client) => {
        const contents = client.db(configuration.mongoDb.db).collection("content");
        let publicMaps = await contents.find({ status: "VERIFIED_OK", public: true }).toArray();
        let privateMaps = await contents.find({ public: false }).toArray();

        const users = client.db(configuration.mongoDb.db).collection("users");
        let undeletedUsers = await users.find({ deleted: false }).toArray();
        let deletedUsers = await users.find({ deleted: true }).toArray();

        res.generatedBaseContent.contents.push({
            maps: {
                public: publicMaps.length,
                private: privateMaps.length
            },
            users: {
                undeleted: undeletedUsers.length,
                deleted: deletedUsers.length,
                online: onlineUsers.length
            }
        });

        res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
        res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;

        res.send(res.generatedBaseContent);
        client.close();
    })
})

app.post("/public/register", async (req, res) => {
    MongoClient.connect(configuration.mongoDb.server, async (error, client) => {
        req.body.password = await bcrypt.hash(req.body.password, 6);
        req.body.contents = [];

        req.body.deleted = false;

        const collection = client.db(configuration.mongoDb.db).collection("users");
        await collection.insertOne(req.body);
        
        res.generatedBaseContent.requestInfo.generatedJWTtoken = jwt.sign({
            email: req.body.email,
            password: req.body.password,
            expiration: Date.now() + 10800000 // 3 hours will works
        }, configuration.key)

        res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
        res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;

        res.send(res.generatedBaseContent);
        client.close();
    })
})

// private functions of server

app.use("/private/", async (req, res, next) => {
    try {
        switch (req.headers["authorization"].split(" ")[0]) {
            case "Basic":
                var authorization = req.headers["authorization"].split(" ")[1];
                const authorizationInfo = Buffer.from(authorization, "base64").toString("ascii").split(":");

                MongoClient.connect(configuration.mongoDb.server, async (error, client) => {
                    const collection = client.db(configuration.mongoDb.db).collection("users");
                    const user = await collection.findOne({ email: authorizationInfo[0] })

                    if (user) {
                        var passwordMatch = await bcrypt.compare(authorizationInfo[1], user.password);
                        if (passwordMatch == false) {
                            res.generatedBaseContent.error = {
                                code: 1150,
                                message: "Invaild password",
                                errorRes: {
                                    name: null,
                                    message: null
                                }
                            };

                            res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
                            res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;

                            client.close()
                            return res.status(500).send(res.generatedBaseContent);
                        }
                    } else {
                        res.generatedBaseContent.error = {
                            code: 1100,
                            message: "Invaild email",
                            errorRes: {
                                name: null,
                                message: null
                            }
                        };

                        res.generatedBaseContent.requestInfo.authorization = false;

                        res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
                        res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;

                        client.close()
                        return res.status(401).send(res.generatedBaseContent);
                    }

                    req.email = user.email;
                    req.password = user.password;

                    res.generatedBaseContent.requestInfo.authorization = true;
                    res.generatedBaseContent.requestInfo.generatedJWTtoken = jwt.sign({
                        email: authorizationInfo[0],
                        password: user.password,
                        expiration: Date.now() + 10800000 // 3 hours will works
                    }, configuration.key)

                    client.close();
                    next()
                })
                break;
            case "JWT":
                var authorization = req.headers["authorization"].split(" ")[1];

                MongoClient.connect(configuration.mongoDb.server, async (error, client) => {
                    const collection = client.db(configuration.mongoDb.db).collection("users");

                    try {
                        const token = await jwt.verify(authorization, configuration.key);
                        const user = await collection.findOne({ email: token.email })
                        if (token.expiration < Date.now()) {
                            res.generatedBaseContent.error = {
                                code: 1250,
                                message: "Bad authorization token",
                                errorRes: {
                                    name: null,
                                    message: null
                                }
                            };

                            res.generatedBaseContent.requestInfo.authorization = false;

                            res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
                            res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;

                            client.close()
                            return res.status(401).send(res.generatedBaseContent);
                        }
                        if (user == null) {
                            res.generatedBaseContent.error = {
                                code: 1100,
                                message: "Invaild email",
                                errorRes: {
                                    name: null,
                                    message: null
                                }
                            };

                            res.generatedBaseContent.requestInfo.authorization = false;

                            res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
                            res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;

                            client.close()
                            return res.status(401).send(res.generatedBaseContent);
                        }

                        req.email = token.email;
                        req.password = token.password;

                        res.generatedBaseContent.requestInfo.authorization = true;

                        client.close();
                        next()
                    } catch (error) {
                        res.generatedBaseContent.error = {
                            code: 1200,
                            message: "Invaild authorization token",
                            errorRes: {
                                name: null,
                                message: null
                            }
                        };

                        res.generatedBaseContent.requestInfo.authorization = false;

                        res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
                        res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;

                        client.close()
                        return res.status(401).send(res.generatedBaseContent);
                    }
                })
                break;
        }
    } catch (error) {
        res.generatedBaseContent.error = {
            code: 1005,
            message: "Authorization required",
            errorRes: {
                name: null,
                message: null
            }
        }

        res.generatedBaseContent.requestInfo.authorization = false;

        res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
        res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;

        res.status(401).send(res.generatedBaseContent);
    }
})

app.use("/private/", async (req, res, next) => {
    for (let i = 0; i < onlineUsers; i++) {
        if (onlineUsers[i].lastRequestTime - Date.now() > 300000) {
            onlineUsers.pop(i);
        }
    }
    next();
})

app.get("/private/ping", async (req, res) => {
    MongoClient.connect(configuration.mongoDb.server, async (error, client) => {
        const collection = client.db(configuration.mongoDb.db).collection("users");
        const user = await collection.findOne({ email: req.email })

        if (user) {
            let exists;
            for (let i = 0; i < onlineUsers.length; i++) {
                if (onlineUsers[i].email == req.email && onlineUsers[i].password == req.password) {
                    onlineUsers[i].lastRequestTime = Date.now();
                    exists = true;
                    break;
                }
            }
            if (exists != true) {
                onlineUsers.push({
                    email: req.email,
                    password: req.password,
                    lastRequestTime: Date.now()
                })
            }

            res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
            res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;

            res.send(res.generatedBaseContent);
        } else {
            res.generatedBaseContent.error = {
                code: 1500,
                message: "User is not registered",
                errorRes: {
                    name: null,
                    message: null
                }
            };

            res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
            res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;

            client.close()
            return res.status(500).send(res.generatedBaseContent);
        }
    })
})

app.route("/private/user")
    .get(async (req, res) => {
        switch (req.query.q) {
            case "getUsers":
                MongoClient.connect(configuration.mongoDb.server, async (error, client) => {
                    const collection = client.db(configuration.mongoDb.db).collection("users");
                    for await (var _id of req.query._ids.split(",")) {
                        const user = await collection.findOne({ _id: new ObjectId(_id) }, { projection: { password: false } })
                        res.generatedBaseContent.contents.push(user)
                    }
                    res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
                    res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;
                    res.send(res.generatedBaseContent);
                })
                break;
            case "getCurrentUser":
                MongoClient.connect(configuration.mongoDb.server, async (error, client) => {
                    const collection = client.db(configuration.mongoDb.db).collection("users");
                    const user = await collection.findOne({ email: req.email }, { projection: { password: false } })
                    res.generatedBaseContent.contents.push(user)
                    res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
                    res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;
                    res.send(res.generatedBaseContent);
                })
                break;
            default:
                res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
                res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;
                res.status(404).send(res.generatedBaseContent);
                break;
        }
    })
    .patch(async (req, res) => {
        switch (req.query.q) {
            case "updateCurrentUser":
                // removing this for secruity
                req.body.email = undefined;
                req.body.password = undefined;
                req.body.contents = undefined;

                MongoClient.connect(configuration.mongoDb.server, async (error, client) => {
                    const collection = client.db(configuration.mongoDb.db).collection("users");
                    const command = await collection.findOneAndUpdate({ email: req.email }, { $set: req.body })
                    
                    res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
                    res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;
                    
                    res.send(res.generatedBaseContent);
                })
                break;
            case "updatePassword":
                var password = await bcrypt.hash(req.query.new, 6);
                MongoClient.connect(configuration.mongoDb.server, async (error, client) => {
                    const collection = client.db(configuration.mongoDb.db).collection("users");
                    const command = await collection.findOneAndUpdate({ email: req.email }, { $set: { password: password } })
                    
                    res.generatedBaseContent.requestInfo.generatedJWTtoken = jwt.sign({
                        email: req.email,
                        password: password,
                        expiration: Date.now() + 10800000 // 3 hours will works
                    }, configuration.key)

                    res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
                    res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;
                    
                    res.send(res.generatedBaseContent);
                })
                break;
            case "updateEmail":
                MongoClient.connect(configuration.mongoDb.server, async (error, client) => {
                    const collection = client.db(configuration.mongoDb.db).collection("users");
                    const command = await collection.findOneAndUpdate({ email: req.email }, { $set: { email: req.query.new } })
                    
                    res.generatedBaseContent.requestInfo.generatedJWTtoken = jwt.sign({
                        email: req.query.new,
                        password: req.password,
                        expiration: Date.now() + 10800000 // 3 hours will works
                    }, configuration.key)

                    res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
                    res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;
                        
                    res.send(res.generatedBaseContent);
                })
                break;
            default:
                res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
                res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;
                res.status(404).send(res.generatedBaseContent);
                break;
        }
    })
    .delete(async (req, res) => {
        switch (req.query.q) {
            case "deleteCurrentUser":
                MongoClient.connect(configuration.mongoDb.server, async (error, client) => {
                    const collection = client.db(configuration.mongoDb.db).collection("users");
                    const command = await collection.findOneAndReplace({ email: req.email }, { $set: { deleted: true } })
                    
                    res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
                    res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;
                    
                    res.send(res.generatedBaseContent);
                })
                break;
            default:
                res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
                res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;
                res.status(404).send(res.generatedBaseContent);
                break;
        }
    })

app.route("/private/content")
    .get(async (req, res) => { 
        switch (req.query.q) {
            case "getPublicArchives":
                MongoClient.connect(configuration.mongoDb.server, async (error, client) => {
                    const collection = client.db(configuration.mongoDb.db).collection("content");
                    for await (var _id of req.query._ids.split(",")) {
                        const content = await collection.findOne({ _id: new ObjectId(_id), status: "VERIFIED_OK", public: true })
                        if (content) {
                            // digitalocean spaces api shit
                            // but here placeholder temporary
                            res.generatedBaseContent.contents.push({
                                "downloadLink": null,
                                "expiresIn": null
                            })
                        } else {
                            res.generatedBaseContent.contents.push({
                                "downloadLink": null,
                                "expiresIn": null
                            })
                        }
                    }
                    res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
                    res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;
                    res.send(res.generatedBaseContent);
                })
                break;
            default:
                res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
                res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;
                res.status(404).send(res.generatedBaseContent);
                break;
        }
    })
    .post(async (req, res) => { })
    .patch(async (req, res) => { })
    .delete(async (req, res) => { })

app.listen(3000);