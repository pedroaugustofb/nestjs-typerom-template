import { MiddlewareConsumer, Module, NestModule, RequestMethod } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { ErrorsInterceptor } from './infra/interceptors/ErrorsInterceptors';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersModule } from './modules/users/users.module';
import AuthMiddleware from './modules/auth/auth.middleware';
import { AuthModule } from './modules/auth/auth.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, envFilePath: '.env' }),
    TypeOrmModule.forRoot({
      // the type of your database must be one of the typeorm supported ex: 'mysql', 'postgres', 'mariadb', 'sqlite', 'oracle', 'mssql', 'mongodb', 'cordova', 'react-native', 'expo', 'nativescript'
      type: process.env.DB_TYPE as any,
      host: process.env.DB_HOST,
      port: parseInt(process.env.DB_PORT),
      username: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      entities: [__dirname + '/**/*.entity{.ts,.js}'],
      synchronize: process.env.DB_SYNC === 'true',
    }),
    AuthModule,
    UsersModule,
  ],
  controllers: [],
  providers: [{ provide: APP_INTERCEPTOR, useClass: ErrorsInterceptor }],
})
// Here we are using the NestModule interface to configure the middleware.
// for example an AuthMiddleware that will be used in all routes except the login and register routes.
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(AuthMiddleware)
      .exclude({ path: 'auth/login', method: RequestMethod.POST }, { path: 'users', method: RequestMethod.POST })
      .forRoutes('*');
  }
}
