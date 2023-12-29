import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class CreateUserDto {
  @IsString()
  @IsNotEmpty()
  @ApiProperty({ example: 'John', required: true })
  name: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty({ example: 'Kennedy', required: true })
  lastName: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty({ example: 'email@teste.com', required: true })
  email: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty({ example: '123456', required: true })
  password: string;
}
