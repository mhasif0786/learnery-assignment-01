import { Controller, Get } from '@nestjs/common';

@Controller('user')
export class UserController {
    @Get("me")
    getme(){
        return "user info"
    }

}
