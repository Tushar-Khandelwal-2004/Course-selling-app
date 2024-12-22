const express=require("express");
const mongoose=require("mongoose");

const {userRouter}=require("./routes/user");
const { courseRouter }=require("./routes/course");
const { adminRouter }=require("./routes/admin");
const app=express();

app.use("/user",userRouter);
app.use("/course",courseRouter);
app.use("/admin",adminRouter);
async function main() {
    await mongoose.connect("mongodb+srv://Tushar:Khan571$@tushar.ivdat.mongodb.net/course-selling-app");
    app.listen(3000);
    console.log("connected");
}
main();