import { ErrorCode } from "../../common/enums/error-code.enum";
import { VerificationEnum } from "../../common/enums/verification-code.enum";
import { LoginDto, RegisterDto } from "../../common/interface/auth.interface";
import { BadRequestException, UnauthorizedException } from "../../common/utils/catch-error";
import { calculateExpirationDate, fortyFiveMinutesFromNow, ONE_DAY_IN_MS } from "../../common/utils/date-time";
import { refreshTokenSignOptions, RefreshTPayload, signJwtToken, verifyJwtToken } from "../../common/utils/jwt";
import { logger } from "../../common/utils/logger";
import { config } from "../../config/app.config";
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

    public async refreshToken(refreshToken: string) {
        const { payload } = verifyJwtToken<RefreshTPayload>(refreshToken, {
            secret: refreshTokenSignOptions.secret,
        });

        if (!payload) {
            throw new UnauthorizedException("Invalid refresh token");
        }

        const session = await SessionModel.findById(payload.sessionId);
        const now = Date.now();

        if (!session) {
            throw new UnauthorizedException("Session does not exist");
        }

        if (session.expiredAt.getTime() <= now) {
            throw new UnauthorizedException("Session expired");
        }

        const sessionRequireRefresh =
        session.expiredAt.getTime() - now <= ONE_DAY_IN_MS;

        if (sessionRequireRefresh) {
            session.expiredAt = calculateExpirationDate(
                config.JWT.REFRESH_EXPIRES_IN
            );
            await session.save();
        }

        const newRefreshToken = sessionRequireRefresh ? signJwtToken(
            {
                sessionId: session._id,
            },
                refreshTokenSignOptions
            )
        : undefined;

        const accessToken = signJwtToken({
            userId: session.userId,
            sessionId: session._id,
        });

        return {
            accessToken,
            newRefreshToken,
        };
    }
}