import { Logger } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';
import CustomValidationPipe from './infra/validation-pipe/CustomValidatePipe';

async function bootstrap() {
  // create the NestJS application
  const app = await NestFactory.create(AppModule);

  // this pipe will automatically transform the payload into a DTO instance
  app.useGlobalPipes(new CustomValidationPipe());

  //doc config by swagger, the url is http://localhost:8080/docs
  const config = new DocumentBuilder().setTitle('API title').setDescription('API Description').setVersion('1.0').build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document);

  // if the port is not defined in the environment, the app will run on port 8080
  const port = process.env.PORT || 8080;

  // create a logger instance
  const logger = new Logger();

  // start the app
  await app.listen(port, () => logger.debug(`Server is running on port ${port}`));
}
bootstrap();
