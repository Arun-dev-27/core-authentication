import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsOptional, IsString, Length, Matches, ValidateIf } from 'class-validator';
import { CLIENT_ID_PATTERN, TRANSACTION_ID_PATTERN } from '@common/constants/validation.constants';

export class EmbedLoginDto {
  @ApiProperty({ example: 'txn-123' })
  @Matches(TRANSACTION_ID_PATTERN)
  transaction_id: string;

  @ApiProperty({ example: 'rms-web-prod' })
  @Matches(CLIENT_ID_PATTERN)
  client_id: string;

  @ApiPropertyOptional({ enum: ['ITS', 'NON_ITS'], default: 'ITS' })
  @IsOptional()
  @IsIn(['ITS', 'NON_ITS'])
  identity_type?: 'ITS' | 'NON_ITS';

  @ApiPropertyOptional({ example: 'ITS12345', description: 'ITS ID (identity_type ITS)' })
  @ValidateIf((o: EmbedLoginDto) => (o.identity_type ?? 'ITS') === 'ITS')
  @Matches(/^[A-Za-z0-9._-]{1,64}$/)
  its_id?: string;

  @ApiPropertyOptional({ example: 'member@example.com', description: 'Username or email (identity_type NON_ITS)' })
  @ValidateIf((o: EmbedLoginDto) => o.identity_type === 'NON_ITS')
  @IsString()
  @Length(3, 256)
  identifier?: string;

  @ApiProperty({ format: 'password' })
  @IsString()
  @Length(1, 256)
  password: string;
}
