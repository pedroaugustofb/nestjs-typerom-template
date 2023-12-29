/* eslint-disable prettier/prettier */
import {
  CallHandler,
  ExecutionContext,
  HttpException,
  Injectable,
  InternalServerErrorException,
  NestInterceptor,
  UnauthorizedException,
  Logger,
  BadRequestException,
} from '@nestjs/common';
import { catchError, Observable } from 'rxjs';

const VALIDATION_PIPE = 'validation-pipe';
// this interceptor will catch all the exceptions and return a 500 error
@Injectable()
export class ErrorsInterceptor implements NestInterceptor {
  private logger = new Logger();

  // this method will check if the error is a validation-pipe error
  private isValidationError = (error: HttpException) =>
    error instanceof BadRequestException && error.getResponse()['source'] === VALIDATION_PIPE;

  // this method will create the log message
  private createLogMessage(context: ExecutionContext, error: HttpException): string {
    const { url, method } = context.switchToHttp().getRequest();
    let log_message = `interceptor > exception > internal server error when trying to access the route: ${url} (method: ${method})`;

    if (this.isValidationError(error)) log_message += ` > validation-pipe error: ${error.getResponse()['erros'].join('; ')}.`;

    log_message += ` error details: ${error.message}`;

    return log_message;
  }

  // this method intercept any error from the application
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      catchError((error: HttpException) => {
        const log_message = this.createLogMessage(context, error);
        this.logger.error(log_message);
        if (error instanceof UnauthorizedException) throw new UnauthorizedException();
        if (this.isValidationError(error)) throw error;

        throw new InternalServerErrorException();
      }),
    );
  }
}
