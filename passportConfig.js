const LocalStrategy = require("passport-local").Strategy;
const {pool} = require("./dbconfig");
const bcrypt = require("bcrypt");
const queries = require("./queries")

function initialize(passport){
    console.log("initialized");
const authenticateUser = (email,password,done)=>{
    pool.query(queries.selectUser,[email],(err,results)=>{
        if(err) throw err;
        console.log(results.rows);
        if(results.rows.length>0){
            const user = results.rows[0];
            bcrypt.compare(password,user.password,(err,isMatch)=>{
                if(err) throw err;
                if(isMatch){
                    return done(null,user);
                }else{
                    return done(null,false,{message:"Password is incorrect"})
                }
            })
        }else{
            return done(null,false,{message:"Email not registered"})
        }
    })
}
    passport.use(
        new LocalStrategy({
            usernameField:"email",
            passwordField:"password"
        },authenticateUser)
    );

    passport.serializeUser((user,done)=> done(null,user.id));
    passport.deserializeUser((id,done)=>{
        pool.query(queries.selectUserById,[id],(err,results)=>{
            if(err) throw err;
            return done(null,results.rows[0]);
        })
    })
}

module.exports = initialize;
