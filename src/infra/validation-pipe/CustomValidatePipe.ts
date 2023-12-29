import { BadRequestException, ValidationError, ValidationPipe } from '@nestjs/common';

export default class CustomValidationPipe extends ValidationPipe {
  createExceptionFactory() {
    return (validationErrors: ValidationError[] = []) => {
      throw new CustomErrorException(validationErrors);
    };
  }
}

export class CustomErrorException extends BadRequestException {
  constructor(public validationErrors: ValidationError[]) {
    super({
      erros: validationErrors.flatMap((error) => Object.values(error.constraints || {})),
      message: 'Validation failed',
      status: 400,
      source: 'validation-pipe',
    });
  }
}
