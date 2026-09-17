import { Column, Entity, JoinColumn, ManyToOne, PrimaryGeneratedColumn, Unique } from 'typeorm';
import { AuthClient } from './auth-client.entity';

export type CallbackUriType = 'CALLBACK' | 'BACK_CHANNEL_LOGOUT' | 'POST_LOGOUT_REDIRECT';

/** `auth_client_callbacks` - registered callback, back-channel logout and post-logout redirect URIs of a client. */
@Entity({ name: 'auth_client_callbacks' })
@Unique('uq_auth_client_callbacks_client_uri_type', ['clientRef', 'uri', 'uriType'])
export class AuthClientCallback {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'client_ref', type: 'uuid' })
  clientRef: string;

  @ManyToOne(() => AuthClient, (client) => client.callbacks, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'client_ref' })
  client: AuthClient;

  @Column({ type: 'varchar', length: 2048 })
  uri: string;

  @Column({ name: 'uri_type', type: 'varchar', length: 32 })
  uriType: CallbackUriType;

  @Column({ name: 'is_primary', type: 'boolean', default: false })
  isPrimary: boolean;

  @Column({ name: 'created_at', type: 'timestamptz', default: () => 'now()' })
  createdAt: Date;
}
