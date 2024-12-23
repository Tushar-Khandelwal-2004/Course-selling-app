const { Router } = require("express");
const { userModel, purchaseModel } = require("../db");
const { z } = require("zod");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const userRouter = Router();
const {JWT_USER_SECRET} = require("../config");
const { userMiddleware } = require("../middleware/user");

userRouter.post("/signup", async function (req, res) {
    const requiredBody = z.object({
        email: z.string().min(11).max(100).email(),
        password: z.string().min(8).max(100),
        firstname: z.string().min(3).max(100),
        lastname: z.string().min(3).max(100),
    });

    const parsedDataWithSuccess = requiredBody.safeParse(req.body);
    if (!parsedDataWithSuccess.success) {
        return res.json({
            success: false,
            error: parsedDataWithSuccess.error.errors
        });
    }

    const { email, password, firstname, lastname } = req.body;

    try {
        // Check if the email already exists in the database
        const existingUser = await userModel.findOne({ where: { email } });
        if (existingUser) {
            return res.json({
                success: false,
                message: "Email is already in use!"
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 5);

        // Create new user
        await userModel.create({
            email: email,
            password: hashedPassword,
            firstname: firstname,
            lastname: lastname
        });

        res.json({
            success: true,
            message: "You have successfully signed up!"
        });

    } catch (e) {
        console.error(e);
        res.json({
            success: false,
            message: "An error occurred while signing up. Please try again later."
        });
    }
})

userRouter.post("/signin", async function (req, res) {
    const { email, password } = req.body;
    const user = await userModel.findOne({
        email: email
    })
    if (!user) {
        res.status(403).send({
            Message: "Incorrect Credentials!"
        })
        return;
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (passwordMatch) {
        const token = jwt.sign({
            id: user._id.toString()
        }, JWT_USER_SECRET);
        res.json({
            token: token
        })
    }
    else {
        res.status(403).send({
            Message: "Incorrect Credentials!"
        })
    }

})

userRouter.get("/purchases",userMiddleware,async function (req, res) {
    const userId=req.userId;
    const purchases=await purchaseModel.find({
        userId
    })
    res.json({
        purchases:purchases
    })
})

module.exports = {
    userRouter: userRouter
}