import { Injectable } from '@nestjs/common';
import { Repository } from 'typeorm';
import { UserEntity } from './user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { CreateUserDto } from '../../dtos/create-user.dto';

@Injectable()
export class UsersRepository {
  constructor(@InjectRepository(UserEntity) private readonly repository: Repository<UserEntity>) {}

  async findOne(options: object): Promise<UserEntity> {
    return await this.repository.findOne({ where: options });
  }

  async create(user: CreateUserDto): Promise<UserEntity> {
    return await this.repository.save(user);
  }
}
