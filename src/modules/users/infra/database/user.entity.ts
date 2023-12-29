import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn } from 'typeorm';

@Entity({ name: 'users' })
export class UserEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ nullable: false })
  name: string;

  @Column({ name: 'last_name', nullable: false })
  lastName: string;

  @Column({ nullable: false })
  email: string;

  @Column({ nullable: false })
  password: string;

  @CreateDateColumn({ name: 'created_at', nullable: false, type: 'timestamp' })
  createdAt: string;

  @UpdateDateColumn({ name: 'update_at' })
  updateAt: string;
}
