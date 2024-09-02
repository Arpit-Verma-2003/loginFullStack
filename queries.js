const selectUser = "SELECT * FROM users WHERE email = $1";
const selectUserById = "SELECT * FROM users WHERE id = $1";
const addUser = "INSERT INTO users(name,email,password) VALUES($1,$2,$3) RETURNING id,password";
module.exports = {
    selectUser,
    selectUserById,
    addUser
}