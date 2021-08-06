var app = require("express")(),
    bcrypt = require('bcrypt'),
    jwt = require("jsonwebtoken"),
    configuration = require("./configuration.json"),
    { MongoClient } = require("mongodb");

// online users
const onlineUsers = [];
let requestIds = 1;

app.use(require("express").json())
    .use(require('nocache')())
    .use(async (req, res, next) => {
        req.startTime = Date.now() / 1000.0;
        res.generatedBaseContent = {
            api: req.url.split("/")[1],
            contents: [],
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
        if (error) {
            res.generatedBaseContent.error = {
                code: 1001,
                message: "Cannot connect to database. Please, try later!",
                errorRes: {
                    name: error.name,
                    message: error.message
                }
            };

            res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
            res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;

            client.close()
            return res.status(500).send(res.generatedBaseContent);
        }
        
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
        if (error) {
            res.generatedBaseContent.error = {
                code: 1001,
                message: "Cannot connect to database. Please, try later!",
                errorRes: {
                    name: error.name,
                    message: error.message
                }
            };

            res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
            res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;

            client.close()
            return res.status(500).send(res.generatedBaseContent);
        }

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

// private functions of server

app.use("/private/", async (req, res, next) => {
    try {
        switch (req.headers["authorization"].split(" ")[0]) {
            case "Basic":
                var authorization = req.headers["authorization"].split(" ")[1];
                const authorizationInfo = Buffer.from(authorization, "base64").toString("ascii").split(":");

                MongoClient.connect(configuration.mongoDb.server, async (error, client) => {
                    if (error) {
                        res.generatedBaseContent.error = {
                            code: 1001,
                            message: "Cannot connect to database. Please, try later!",
                            errorRes: {
                                name: error.name,
                                message: error.message
                            }
                        };
            
                        res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
                        res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;
            
                        client.close()
                        return res.status(500).send(res.generatedBaseContent);
                    }
                    
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
                            
                            res.generatedBaseContent.requestInfo.authorization = false;
    
                            res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
                            res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;
                
                            client.close()
                            return res.status(401).send(res.generatedBaseContent);
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

                    res.generatedBaseContent.requestInfo.authorization = true;
                    res.generatedBaseContent.requestInfo.generatedJWTtoken = jwt.sign({
                        email: authorizationInfo[0],
                        expiration: Date.now() + 10800000 // 3 hours will works
                    }, configuration.keys.public)

                    client.close();
                    next()
                })
            case "JWT":
                var authorization = req.headers["authorization"].split(" ")[1];
                
                MongoClient.connect(configuration.mongoDb.server, async (error, client) => {
                    if (error) {
                        res.generatedBaseContent.error = {
                            code: 1001,
                            message: "Cannot connect to database. Please, try later!",
                            errorRes: {
                                name: error.name,
                                message: error.message
                            }
                        };
            
                        res.generatedBaseContent.timeStatus.serverTime = Date.now() / 1000.0;
                        res.generatedBaseContent.timeStatus.generatedFor = (Date.now() / 1000.0) - req.startTime;
            
                        client.close()
                        return res.status(500).send(res.generatedBaseContent);
                    }
                    
                    const collection = client.db(configuration.mongoDb.db).collection("users");
                    try {
                        const token = await jwt.verify(authorization, configuration.keys.private);
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
                    } catch(error) {
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

                    res.generatedBaseContent.requestInfo.authorization = true;

                    client.close();
                    next()
                })
        }
    } catch(error) {
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

// TODO: make this
app.route("/private/user")
app.route("/private/comment")
app.route("/private/content")

app.listen(3000);