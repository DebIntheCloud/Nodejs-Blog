// const mongoose = require ('mongoose');

// const Schema = mongoose.Schema;
// const UserSchema = new Schema({
//     username: {
//         type: String,
//         required: true,
//         unique: true
//     },
//     password: {
//         type: String,
//         required: true,
//     }
// });

// module.exports = mongoose.model('User', UserSchema);

const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const UserSchema = new Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true,
    },
    role: {
        type: String,
        default: 'admin'
    }
});

module.exports = mongoose.model('User', UserSchema);
