import bcrypt from "bcryptjs"; // Cambiado a bcryptjs
import crypto from "crypto";
import mongoose, { Document, Schema } from "mongoose";

export type UserDocument = Document & {
    email: string;
    password: string;
    passwordResetToken: string;
    passwordResetExpires: Date;

    facebook: string;
    twitter: string;
    google: string;
    tokens: AuthToken[];

    profile: {
        name: string;
        gender: string;
        location: {
            type: string;
            coordinates: [number, number];
        };
        website: string;
        picture: string;
    };

    comparePassword: comparePasswordFunction;
    gravatar: (size: number) => string;
};

type comparePasswordFunction = (candidatePassword: string, cb: (err: Error | null, isMatch: boolean) => void) => void;

export interface AuthToken {
    accessToken: string;
    kind: string;
}

const userSchema = new Schema<UserDocument>(
    {
        email: { type: String, unique: true, required: true, match: [/.+\@.+\..+/, "Please fill a valid email address"] },
        password: { type: String, required: true, minlength: 6 },
        passwordResetToken: String,
        passwordResetExpires: Date,
    
        facebook: String,
        twitter: String,
        google: String,
        tokens: [{ accessToken: String, kind: String }],
    
        profile: {
            name: String,
            gender: String,
            location: {
                type: { type: String, enum: ["Point"], required: true },
                coordinates: { type: [Number], required: true }
            },
            website: String,
            picture: String
        }
    },
    { timestamps: true },
);

/**
 * Password hash middleware.
 */
userSchema.pre("save", function save(next) {
    const user = this as UserDocument;
    if (!user.isModified("password")) { return next(); }
    bcrypt.genSalt(10, (err: Error | null, salt: string) => {
        if (err) { return next(err); }
        bcrypt.hash(user.password, salt, (err: Error | null, hash: string) => {
            if (err) { return next(err); }
            user.password = hash;
            next();
        });
    });
});

const comparePassword: comparePasswordFunction = function (candidatePassword, cb) {
    bcrypt.compare(candidatePassword, this.password, (err: Error | null, isMatch: boolean) => {
        cb(err, isMatch);
    });
};

userSchema.methods.comparePassword = comparePassword;

/**
 * Helper method for getting user's gravatar.
 */
userSchema.methods.gravatar = function (size: number = 200) {
    if (!this.email) {
        return `https://gravatar.com/avatar/?s=${size}&d=retro`;
    }
    const md5 = crypto.createHash("md5").update(this.email).digest("hex");
    return `https://gravatar.com/avatar/${md5}?s=${size}&d=retro`;
};

export const User = mongoose.model<UserDocument>("User", userSchema);
