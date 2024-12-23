const { Router } = require("express");
const { adminModel, courseModel } = require("../db");
const { z } = require("zod");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const {JWT_ADMIN_SECRET} = require("../config");
const adminRouter = Router();
const{ adminMiddleware }=require("../middleware/admin");
const admin = require("../middleware/admin");


adminRouter.post("/signup", async function (req, res) {
    const requiredBody = z.object({
        email: z.string().min(11).max(200).email(),
        password: z.string().min(8).max(100),
        firstname: z.string().min(3).max(100),
        lastname: z.string().min(3).max(100)
    })
    const parsedDataWithSuccess = requiredBody.safeParse(req.body);
    if (!parsedDataWithSuccess.success) {
        return res.json({
            success: false,
            error: parsedDataWithSuccess.error.errors
        });
    }
    const { email, password, firstname, lastname } = parsedDataWithSuccess.data;

    try {
        const user = await adminModel.findOne({ where: { email } });
        if (user) {
            return res.json({
                success: false,
                message: "Email is already in use!"
            });
        }

        const hashedPassword = await bcrypt.hash(password, 5);
        await adminModel.create({
            email: email,
            password: hashedPassword,
            firstname: firstname,
            lastname: lastname
        });
        res.json({
            success: true,
            message: "You have successfully signed up!"
        });
    }
    catch (e) {
        console.error(e);
        res.json({
            success: false,
            message: "An error occurred while signing up. Please try again later."
        });
    }
})

adminRouter.post("/signin", async function (req, res) {
    const { email, password } = req.body;
    const user = await adminModel.findOne({
        email: email
    })
    if (!user) {
        return res.status(403).send({
            message: "Incorrect Credentials!!"
        })
    }
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (passwordMatch) {
        const token = jwt.sign({
            id: user._id.toString()
        }, JWT_ADMIN_SECRET);
        res.json({
            token: token,
            message: "You have signed in!"
        })
    }
    else {
        res.status(403).send({
            Message: "Incorrect Credentials!"
        })
    }
})

adminRouter.post("/course", adminMiddleware ,async function (req, res) {
    const adminId=req.userId;
    const {title , description , imageUrl , price}=req.body;
    const course=await courseModel.create({
        title:title,
        description:description,
        imageUrl:imageUrl,
        price:price,
        creatorId:adminId
    })
    res.json({
        message:"Course Created!",
        courseId:course._id

    })
})

adminRouter.put("/course",adminMiddleware ,async function (req, res) {
    const adminId=req.userId;
    const {title , description , imageUrl , price , courseId}=req.body;
    const course=await courseModel.updateOne({
        _id:courseId,
        creatorId:adminId
    },{
        title:title,
        description:description,
        imageUrl:imageUrl,
        price:price,
        creatorId:adminId
    })
    res.json({
        message:"Course Updated!",
        courseId:course._id

    })
    res.json({
        message: "signup endpoint"
    })
})

adminRouter.get("/course/bulk", adminMiddleware ,async function (req, res) {
    const adminId=req.userId;
    const courses=courseModel.find({
        creatorId:adminId
    });
    res.json({
        courses
    })
})

module.exports = {
    adminRouter: adminRouter
}