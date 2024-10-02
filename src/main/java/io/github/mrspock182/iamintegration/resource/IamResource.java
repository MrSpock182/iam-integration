package io.github.mrspock182.iamintegration.resource;

import com.amazonaws.services.identitymanagement.model.CreateUserResult;
import io.github.mrspock182.iamintegration.service.IamActiveService;
import io.github.mrspock182.iamintegration.service.IamService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/iam/user")
public class IamResource {
    private final IamService iamService;
    private final IamActiveService iamActiveService;

    public IamResource(IamService iamService, IamActiveService iamActiveService) {
        this.iamService = iamService;
        this.iamActiveService = iamActiveService;
    }

    @GetMapping
    @ResponseStatus(HttpStatus.CREATED)
    public CreateUserResult createUser(@RequestParam final String userName) {
        return iamService.createUser(userName);
    }

    @DeleteMapping
    @ResponseStatus(HttpStatus.OK)
    public void deleteUser(@RequestParam final String userName) {
        iamService.deleteUser(userName);
    }

    @GetMapping("/enable")
    @ResponseStatus(HttpStatus.OK)
    public void enable(@RequestParam final String userName) {
        iamActiveService.enableUserWithNewAccessKey(userName);
    }

    @PatchMapping
    @ResponseStatus(HttpStatus.OK)
    public void resetPassword(@RequestParam final String userName) {
        iamActiveService.createNewKey(userName);
    }

}