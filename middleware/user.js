const jwt=require("jsonwebtoken");
const { JWT_USER_SECRET }=require("../config");

function userMiddleware(req,res,next){
    const token=req.headers.token;
    const decodedInfo=jwt.verify(token,JWT_USER_SECRET);
    if(decodedInfo){
        req.userId=decodedInfo.id;
        next();
    }
    else{
        res.status(403).send({
            message:"You are not signed in!"
        })
    }
}

module.exports={
    userMiddleware:userMiddleware
}