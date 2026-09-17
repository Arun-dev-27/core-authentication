import { Column, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn, Unique } from 'typeorm';
import { AuthClient } from './auth-client.entity';

/** `auth_client_origins` - an exact origin allowed to embed the login iframe and receive the postMessage. */
@Entity({ name: 'auth_client_origins' })
@Unique('uq_auth_client_origins_client_origin', ['clientRef', 'origin'])
export class AuthClientOrigin {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'client_ref', type: 'uuid' })
  clientRef: string;

  @ManyToOne(() => AuthClient, (client) => client.origins, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'client_ref' })
  client: AuthClient;

  @Column({ type: 'varchar', length: 512 })
  origin: string;

  @Column({ name: 'created_at', type: 'timestamptz', default: () => 'now()' })
  createdAt: Date;
}
