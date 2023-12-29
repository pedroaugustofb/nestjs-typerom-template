import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class LoginDto {
  @IsString()
  @IsNotEmpty()
  @ApiProperty({ example: 'email@teste.com', required: true })
  email: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty({ example: '123456', required: true })
  password: string;
}
