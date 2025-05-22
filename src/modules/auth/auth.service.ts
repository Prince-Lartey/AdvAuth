import { ErrorCode } from "../../common/enums/error-code.enum";
import { VerificationEnum } from "../../common/enums/verification-code.enum";
import { LoginDto, RegisterDto } from "../../common/interface/auth.interface";
import { BadRequestException } from "../../common/utils/catch-error";
import { fortyFiveMinutesFromNow } from "../../common/utils/date-time";
import { refreshTokenSignOptions, signJwtToken } from "../../common/utils/jwt";
import { logger } from "../../common/utils/logger";
import SessionModel from "../../database/models/session.model";
import UserModel from "../../database/models/user.model";
import VerificationCodeModel from "../../database/models/verification.model";

export class AuthService {
    public async register(registerData: RegisterDto) {
        const { name, email, password } = registerData;

        const existingUser = await UserModel.exists({
            email,
        });

        if (existingUser) {
            throw new BadRequestException(
                "User already exists with this email",
                ErrorCode.AUTH_EMAIL_ALREADY_EXISTS
            );
        }
        const newUser = await UserModel.create({
            name,
            email,
            password,
        });

        const userId = newUser._id;

        const verification = await VerificationCodeModel.create({
            userId,
            type: VerificationEnum.EMAIL_VERIFICATION,
            expiresAt: fortyFiveMinutesFromNow(),
        });



        return {
            user: newUser,
        };
    }

    public async login(loginData: LoginDto) {
        const { email, password, userAgent } = loginData;

        logger.info(`Login attempt for email: ${email}`);
        const user = await UserModel.findOne({
            email: email,
        });

        if (!user) {
            logger.warn(`Login failed: User with email ${email} not found`);
            throw new BadRequestException(
                "Invalid email or password provided",
                ErrorCode.AUTH_USER_NOT_FOUND
            );
        }

        const isPasswordValid = await user.comparePassword(password);
        if (!isPasswordValid) {
            logger.warn(`Login failed: Invalid password for email: ${email}`);
            throw new BadRequestException(
                "Invalid email or password provided",
                ErrorCode.AUTH_USER_NOT_FOUND
            );
        }

        // Check if the user enable 2fa retuen user= null
        if (user.userPreferences.enable2FA) {
            logger.info(`2FA required for user ID: ${user._id}`);
            return {
                user: null,
                mfaRequired: true,
                accessToken: "",
                refreshToken: "",
            };
        }

        logger.info(`Creating session for user ID: ${user._id}`);
        const session = await SessionModel.create({
            userId: user._id,
            userAgent,
        });

        logger.info(`Signing tokens for user ID: ${user._id}`);
        const accessToken = signJwtToken({
            userId: user._id,
            sessionId: session._id,
        });

        const refreshToken = signJwtToken(
        {
            sessionId: session._id,
        },
            refreshTokenSignOptions
        );

        logger.info(`Login successful for user ID: ${user._id}`);
        return {
            user,
            accessToken,
            refreshToken,
            mfaRequired: false,
        };
    }
}