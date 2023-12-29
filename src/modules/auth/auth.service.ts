import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { UsersRepository } from '../users/infra/database/user.repository';
import { LoginDto } from './dtos/login.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  private logger = new Logger();
  constructor(private readonly usersRepository: UsersRepository) {}

  async login(login: LoginDto) {
    if (!login.email) throw new Error('Email is required.');

    const user = await this.usersRepository.findOne({ email: login.email });

    if (!user) throw new Error('User not found.');

    const isPasswordValid = bcrypt.compareSync(login.password, user.password);

    if (!isPasswordValid) throw new UnauthorizedException('Invalid password.');

    this.logger.verbose(`user logged in > ${user.email}`);

    // here you can do whatever you want with the user data like generate a token
    return user;
  }
}
