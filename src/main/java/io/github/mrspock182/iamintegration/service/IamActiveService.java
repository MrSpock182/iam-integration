package io.github.mrspock182.iamintegration.service;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagement;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClientBuilder;
import com.amazonaws.services.identitymanagement.model.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class IamActiveService {

    private static final String POLICY_ARN = "arn:aws:iam::103120217022:policy/AccessAPI";

    private final AmazonIdentityManagement iam;

    public IamActiveService(
            @Value("${aws.accessKeyId}") String accessKeyId,
            @Value("${aws.secretAccessKey}") String secretAccessKey,
            @Value("${aws.region}") String region) {
        final BasicAWSCredentials credentials = new BasicAWSCredentials(accessKeyId, secretAccessKey);
        this.iam = AmazonIdentityManagementClientBuilder.standard()
                .withRegion(Regions.fromName(region))
                .withCredentials(new AWSStaticCredentialsProvider(credentials))
                .build();
    }

    public void enableUserWithNewAccessKey(String userName) {
        createOrResetConsolePassword(userName, UUID.randomUUID().toString());
        CreateAccessKeyResult createAccessKeyResult = createNewAccessKey(userName);
        reattachUserPolicy(userName, POLICY_ARN);

        System.out.println(createAccessKeyResult.getAccessKey().getAccessKeyId());
        System.out.println(createAccessKeyResult.getAccessKey().getSecretAccessKey());
    }


    public void createNewKey(String userName) {
        CreateAccessKeyResult createAccessKeyResult = createNewAccessKey(userName);

        System.out.println(createAccessKeyResult.getAccessKey().getAccessKeyId());
        System.out.println(createAccessKeyResult.getAccessKey().getSecretAccessKey());
    }

    public CreateAccessKeyResult createNewAccessKey(String userName) {
        CreateAccessKeyRequest createAccessKeyRequest = new CreateAccessKeyRequest().withUserName(userName);
        return iam.createAccessKey(createAccessKeyRequest);
    }

    private void createOrResetConsolePassword(String userName, String newPassword) {
        try {
            CreateLoginProfileRequest createLoginProfileRequest = new CreateLoginProfileRequest()
                    .withUserName(userName)
                    .withPassword(newPassword)
                    .withPasswordResetRequired(true);
            iam.createLoginProfile(createLoginProfileRequest);
        } catch (EntityAlreadyExistsException e) {
            UpdateLoginProfileRequest updateLoginProfileRequest = new UpdateLoginProfileRequest()
                    .withUserName(userName)
                    .withPassword(newPassword)
                    .withPasswordResetRequired(true);
            iam.updateLoginProfile(updateLoginProfileRequest);
        }
    }

    private void reattachUserPolicy(String userName, String policyArn) {
        AttachUserPolicyRequest attachUserPolicyRequest = new AttachUserPolicyRequest()
                .withUserName(userName)
                .withPolicyArn(policyArn);
        iam.attachUserPolicy(attachUserPolicyRequest);
    }

}
