import { ApiProperty } from '@nestjs/swagger';
import { Matches } from 'class-validator';
import { TRANSACTION_ID_PATTERN } from '@common/constants/validation.constants';

export class EmbedLogoutDto {
  @ApiProperty()
  @Matches(TRANSACTION_ID_PATTERN)
  transaction_id: string;
}
