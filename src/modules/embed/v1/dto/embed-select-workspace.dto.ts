import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsUUID, Matches, ValidateIf } from 'class-validator';
import { CLIENT_ID_PATTERN, TRANSACTION_ID_PATTERN } from '@common/constants/validation.constants';

const SCOPE_TYPES = ['CORE', 'BUSINESS_UNIT', 'UTILITY'] as const;
export type SelectableScopeType = (typeof SCOPE_TYPES)[number];

/**
 * Embedded login, step 2: the workspace the user picked. Every value is re-validated against the
 * database for the authenticated session - none of it is trusted because the browser sent it.
 */
export class EmbedSelectWorkspaceDto {
  @ApiProperty({ example: 'txn-123' })
  @Matches(TRANSACTION_ID_PATTERN)
  transaction_id: string;

  @ApiProperty({ example: 'rms-web-prod' })
  @Matches(CLIENT_ID_PATTERN)
  client_id: string;

  @ApiProperty()
  @IsUUID()
  role_id: string;

  @ApiProperty({ enum: SCOPE_TYPES })
  @IsIn(SCOPE_TYPES)
  scope_type: SelectableScopeType;

  @ApiPropertyOptional({ nullable: true })
  @ValidateIf((o: EmbedSelectWorkspaceDto) => o.scope_type !== 'CORE' || (o.scope_id !== undefined && o.scope_id !== null))
  @IsUUID()
  scope_id?: string | null;
}
