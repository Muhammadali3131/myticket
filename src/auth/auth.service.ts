import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from "@nestjs/common";
import { AdminDocument } from "../admin/schemas/admin.schema";
import { JwtService } from "@nestjs/jwt";
import { CreateAdminDto } from "../admin/dto/create-admin.dto";
import { AdminService } from "../admin/admin.service";
import * as bcrypt from "bcrypt";
import { LoginAdminDto } from "../admin/dto/login-admin.dto";
import { Response } from "express";

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly adminService: AdminService
  ) {}
  private async generateTokens(admin: AdminDocument) {
    const payload = {
      id: admin._id,
      is_avtive: admin.is_active,
      is_creator: admin.is_creator,
    };
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: process.env.ACCESS_TOKEN_KEY,
        expiresIn: process.env.ACCESS_TOKEN_TIME,
      }),
      this.jwtService.signAsync(payload, {
        secret: process.env.REFRESH_TOKEN_KEY,
        expiresIn: process.env.REFRESH_TOKEN_TIME,
      }),
    ]);
    return {
      accessToken,
      refreshToken,
    };
  }

  async registration(createAdminDto: CreateAdminDto) {
    const candidate = await this.adminService.findByEmail(createAdminDto.email);
    if (candidate) {
      throw new ConflictException(
        "Bunday email avval tizimda ro'yxatdan o'tgan"
      );
    }
    const admin = await this.adminService.create(createAdminDto);
    return { adminId: admin._id };
  }

  async login(loginAdminDto: LoginAdminDto, res: Response) {
    const admin = await this.adminService.findByEmail(loginAdminDto.email);
    if (!admin) {
      throw new UnauthorizedException("Email yoki Password noto'g'ri");
    }

    const isValidPassword = await bcrypt.compare(
      loginAdminDto.password,
      admin.hashed_password
    );

    if (!isValidPassword) {
      throw new UnauthorizedException("Email yoki Password noto'g'ri");
    }

    const { accessToken, refreshToken } = await this.generateTokens(admin);
    admin.hashed_refresh_Token = await bcrypt.hash(refreshToken, 7);

    await admin.save();
    res.cookie("refreshToken", refreshToken, {
      maxAge: +process.env.COOKIE_TIME!,
      httpOnly: true,
    });

    return { adminId: admin._id, accessToken };
  }
}
