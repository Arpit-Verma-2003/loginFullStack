const express = require("express");
const path = require("path");
const PORT = process.env.PORT || 4000;
const {pool} = require("./dbconfig");
const bcrypt = require("bcrypt");
const queries = require("./queries");
const session = require("express-session");
const flash = require("express-flash");

const app = express();

app.set("view engine", "ejs");
app.use(express.urlencoded({extended:false}))
app.use(session({
  secret : "secret",
  resave: false,
  saveUninitialized: false
}))
app.use(flash());
app.get("/", (req, res) => {
  return res.render("index");
});

app.get("/users/login", (req, res) => {
  return res.render("login");
});

app.get("/users/register", (req, res) => {
  return res.render("register");
});

app.get("/users/dashboard", (req, res) => {
  return res.render("dashboard",{ user : "Arpit"});
});

app.post("/users/register", async (req,res)=>{
  let {name,mail,password,password2} = req.body;
  console.log({name,mail,password,password2});
  let errors = [];
  if(!name||!mail||!password||!password2){
    errors.push({message:"Please fill all the fields"});
  }
  if(password.length < 4){
    errors.push({message:"Password should have 4 minimum characters"});
  }
  if(password!=password2){
    errors.push({message:"Passwords do not match"});
  }
  if(errors.length>0){
    res.render("register",{errors});
  }else{
    let hashedPassword = await bcrypt.hash(password,10);
    console.log(hashedPassword);
    pool.query(
      queries.selectUser,[mail],(err,results)=>{
        if(err) throw err;
        console.log(results.rows);
        if(results.rows.length>0){
          errors.push({message:"Email already registered"});
          res.render("register",{errors});
        }else{
          pool.query(queries.addUser,[name,mail,hashedPassword],(err,results)=>{
            if(err) throw err;
            console.log(results.rows);
            req.flash("success_msg","You are successfully registered , Kindly login");
            res.redirect("/users/login");
          })
        }
      }
    )
  }
})

app.listen(PORT, () => {
  console.log(`server listening at : ${PORT}`);
});
