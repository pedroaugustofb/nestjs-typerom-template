import { Injectable, Logger } from '@nestjs/common';
import { UsersRepository } from './infra/database/user.repository';
import { ConfigService } from '@nestjs/config';
import { CreateUserDto } from './dtos/create-user.dto';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
  private logger = new Logger();

  constructor(private readonly usersRepository: UsersRepository, private config: ConfigService) {}

  async createUser(user: CreateUserDto) {
    try {
      // here we can add some business logic
      if (await this.usersRepository.findOne({ email: user.email })) throw new Error('User already exists');

      return await this.usersRepository.create({
        ...user,
        password: await bcrypt.hash(user.password, Number(this.config.get('PASSWORD_SALT'))),
      });
    } catch (error) {
      throw error;
    }
  }
}
