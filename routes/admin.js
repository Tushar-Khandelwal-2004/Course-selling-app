const { Router } = require("express");
const { adminModel } = require("../db");
const { z } = require("zod");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const JWT_SECRET = "AdminTheDon";
const adminRouter = Router();


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
            id: user._id
        }, JWT_SECRET);
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

adminRouter.post("/course", function (req, res) {
    res.json({
        message: "signup endpoint"
    })
})

adminRouter.put("/course", function (req, res) {
    res.json({
        message: "signup endpoint"
    })
})

adminRouter.get("/course/bulk", function (req, res) {
    res.json({
        message: "signup endpoint"
    })
})

module.exports = {
    adminRouter: adminRouter
}