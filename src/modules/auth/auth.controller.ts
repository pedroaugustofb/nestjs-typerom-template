import { Body, Controller, Logger, Post, Res } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { LoginDto } from './dtos/login.dto';

@Controller('auth')
@ApiTags('auth')
export default class AuthController {
  private logger = new Logger();

  constructor(private readonly authService: AuthService) {}

  @Post('login')
  @ApiOperation({ summary: 'Try to login an user.' })
  @ApiResponse({ status: 200, description: 'User logged in successfully.' })
  @ApiResponse({ status: 404, description: 'Bad Request.' })
  async login(@Res() response, @Body() login: LoginDto) {
    this.logger.log(`loggin user > ${login.email}`);

    const data = await this.authService.login(login);

    // return data without password
    delete data.password;

    return response.status(200).json({
      status: 200,
      message: 'User logged in successfully.',
      data,
    });
  }
}
