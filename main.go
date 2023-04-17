package main

import (
	"fmt"

	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/apigateway"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/cloudwatch"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/cognito"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/iam"
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/lambda"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

var (
	appName = "localemgmt"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		userpool, err := createCognito(ctx)
		if err != nil {
			return err
		}

		lambdaFunc, err := createLambda(ctx)
		if err != nil {
			return err
		}

		err = createApiGateway(ctx, lambdaFunc, userpool)
		if err != nil {
			return err
		}

		return nil
	})
}

func getAppPrefixName(ctx *pulumi.Context) string {
	return fmt.Sprintf("%s-%s-", ctx.Stack(), appName)
}

func createCognito(ctx *pulumi.Context) (*cognito.UserPool, error) {

	userpoolname := fmt.Sprintf("%s-user-pool", getAppPrefixName(ctx))
	userpoolClientname := fmt.Sprintf("%s-user-pool-client", getAppPrefixName(ctx))

	userpool, err := cognito.NewUserPool(
		ctx,
		userpoolname,
		&cognito.UserPoolArgs{
			Name: pulumi.String(userpoolname),
			AccountRecoverySetting: &cognito.UserPoolAccountRecoverySettingArgs{
				RecoveryMechanisms: cognito.UserPoolAccountRecoverySettingRecoveryMechanismArray{
					&cognito.UserPoolAccountRecoverySettingRecoveryMechanismArgs{
						Name:     pulumi.String("verified_email"),
						Priority: pulumi.Int(1),
					},
				},
			},
			AutoVerifiedAttributes: pulumi.ToStringArray([]string{"email"}),
		},
	)

	if err != nil {
		return nil, err
	}

	_, err = cognito.NewUserPoolClient(
		ctx,
		userpoolClientname,
		&cognito.UserPoolClientArgs{
			Name:                            pulumi.String(userpoolClientname),
			UserPoolId:                      userpool.ID(),
			ExplicitAuthFlows:               pulumi.ToStringArray([]string{"ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_USER_PASSWORD_AUTH", "ALLOW_USER_SRP_AUTH"}),
			AllowedOauthFlows:               pulumi.ToStringArray([]string{"code", "implicit"}),
			AllowedOauthScopes:              pulumi.ToStringArray([]string{"email", "openid", "profile"}),
			AllowedOauthFlowsUserPoolClient: pulumi.Bool(true),
			EnableTokenRevocation:           pulumi.Bool(true),
			SupportedIdentityProviders:      pulumi.ToStringArray([]string{"COGNITO"}),
			ReadAttributes:                  pulumi.ToStringArray([]string{"email", "email_verified", "family_name", "given_name"}),
			CallbackUrls:                    pulumi.ToStringArray([]string{"https://localhost:3000"}),
			GenerateSecret:                  pulumi.Bool(false),
		})

	if err != nil {
		return nil, err
	}

	_, err = cognito.NewUserPoolDomain(
		ctx,
		fmt.Sprintf("%s-domain", userpoolname),
		&cognito.UserPoolDomainArgs{
			UserPoolId: userpool.ID(),
			Domain:     pulumi.String("localemgmt-userpool-domain"),
		},
	)

	if err != nil {
		return nil, err
	}

	return userpool, nil
}

func createApiGateway(ctx *pulumi.Context, lambdaFunc *lambda.Function, userpool *cognito.UserPool) error {
	apiName := fmt.Sprintf("%s-api-gateway", getAppPrefixName(ctx))

	api, err := apigateway.NewRestApi(ctx, apiName, &apigateway.RestApiArgs{
		Name:        pulumi.String(apiName),
		Description: pulumi.String(appName),
	})

	if err != nil {
		return err
	}

	iamRoleName := fmt.Sprintf("%s-iam-role", apiName)
	policyApiRole := `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "apigateway.amazonaws.com"
      },
      "Effect": "Allow"
    }
  ]
}
`

	apiRole, err := iam.NewRole(ctx, iamRoleName, &iam.RoleArgs{
		Name:              pulumi.String(iamRoleName),
		AssumeRolePolicy:  pulumi.Any(policyApiRole),
		ManagedPolicyArns: pulumi.ToStringArray([]string{"arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"}),
	})

	if err != nil {
		return err
	}

	_, err = apigateway.NewAccount(
		ctx,
		fmt.Sprintf("%s-account", apiName),
		&apigateway.AccountArgs{
			CloudwatchRoleArn: apiRole.Arn,
		},
		pulumi.DependsOn([]pulumi.Resource{api}),
	)

	if err != nil {
		return err
	}

	apiRes, err := apigateway.NewResource(ctx, fmt.Sprintf("%s-resource", apiName), &apigateway.ResourceArgs{
		ParentId: api.RootResourceId,
		PathPart: pulumi.String("locale"),
		RestApi:  api.ID(),
	})

	if err != nil {
		return err
	}

	apiResMessageProxy, err := apigateway.NewResource(ctx, fmt.Sprintf("%s-resource-messages-proxy", apiName), &apigateway.ResourceArgs{
		ParentId: apiRes.ID(),
		PathPart: pulumi.String("{proxy+}"),
		RestApi:  api.ID(),
	})

	if err != nil {
		return err
	}

	apiAuthorizer, err := apigateway.NewAuthorizer(
		ctx,
		fmt.Sprintf("%s-authorizer", apiName),
		&apigateway.AuthorizerArgs{
			Type:         pulumi.String("COGNITO_USER_POOLS"),
			RestApi:      api.ID(),
			ProviderArns: pulumi.ToStringArrayOutput([]pulumi.StringOutput{userpool.Arn.ToStringOutput()}),
		},
	)

	if err != nil {
		return err
	}

	// apiGETMethod, err := apigateway.NewMethod(
	// 	ctx,
	// 	fmt.Sprintf("%s-method-GET", apiName),
	// 	&apigateway.MethodArgs{
	// 		HttpMethod:    pulumi.String("GET"),
	// 		ResourceId:    apiResMessageProxy.ID(),
	// 		RestApi:       api.ID(),
	// 		Authorization: pulumi.String("COGNITO_USER_POOLS"),
	// 		AuthorizerId:  apiAuthorizer.ID(),
	// 	},
	// 	pulumi.Parent(apiResMessageProxy),
	// )

	// if err != nil {
	// 	return err
	// }

	// apiPOSTMethod, err := apigateway.NewMethod(
	// 	ctx,
	// 	fmt.Sprintf("%s-method-POST", apiName),
	// 	&apigateway.MethodArgs{
	// 		HttpMethod:    pulumi.String("POST"),
	// 		ResourceId:    apiResMessageProxy.ID(),
	// 		RestApi:       api.ID(),
	// 		Authorization: pulumi.String("COGNITO_USER_POOLS"),
	// 		AuthorizerId:  apiAuthorizer.ID(),
	// 	},
	// 	pulumi.Parent(apiResMessageProxy),
	// )

	// apiPUTMethod, err := apigateway.NewMethod(
	// 	ctx,
	// 	fmt.Sprintf("%s-method-POST", apiName),
	// 	&apigateway.MethodArgs{
	// 		HttpMethod:    pulumi.String("PUT"),
	// 		ResourceId:    apiResMessageProxy.ID(),
	// 		RestApi:       api.ID(),
	// 		Authorization: pulumi.String("COGNITO_USER_POOLS"),
	// 		AuthorizerId:  apiAuthorizer.ID(),
	// 	},
	// 	pulumi.Parent(apiResMessageProxy),
	// )

	// if err != nil {
	// 	return err
	// }

	// _, err = apigateway.NewIntegration(
	// 	ctx,
	// 	fmt.Sprintf("%s-lambda-integration-POST-proxy", apiName),
	// 	&apigateway.IntegrationArgs{
	// 		RestApi:               api.ID(),
	// 		ResourceId:            apiResMessageProxy.ID(),
	// 		HttpMethod:            pulumi.String("POST"),
	// 		IntegrationHttpMethod: pulumi.String("POST"),
	// 		Type:                  pulumi.String("AWS_PROXY"),
	// 		Uri:                   &lambdaFunc.InvokeArn,
	// 	},
	// 	pulumi.DependsOn([]pulumi.Resource{apiPOSTMethod}),
	// 	pulumi.Parent(apiResMessageProxy),
	// )

	// if err != nil {
	// 	return err
	// }

	// _, err = apigateway.NewIntegration(
	// 	ctx,
	// 	fmt.Sprintf("%s-lambda-integration-GET-proxy", apiName),
	// 	&apigateway.IntegrationArgs{
	// 		RestApi:               api.ID(),
	// 		ResourceId:            apiResMessageProxy.ID(),
	// 		HttpMethod:            pulumi.String("POST"),
	// 		IntegrationHttpMethod: pulumi.String("POST"),
	// 		Type:                  pulumi.String("AWS_PROXY"),
	// 		Uri:                   &lambdaFunc.InvokeArn,
	// 	},
	// 	pulumi.DependsOn([]pulumi.Resource{apiGETMethod}),
	// 	pulumi.Parent(apiResMessageProxy),
	// )

	// if err != nil {
	// 	return err
	// }

	// _, err = apigateway.NewIntegration(
	// 	ctx,
	// 	fmt.Sprintf("%s-lambda-integration-PUT-proxy", apiName),
	// 	&apigateway.IntegrationArgs{
	// 		RestApi:               api.ID(),
	// 		ResourceId:            apiResMessageProxy.ID(),
	// 		HttpMethod:            pulumi.String("PUT"),
	// 		IntegrationHttpMethod: pulumi.String("PUT"),
	// 		Type:                  pulumi.String("AWS_PROXY"),
	// 		Uri:                   &lambdaFunc.InvokeArn,
	// 	},
	// 	pulumi.DependsOn([]pulumi.Resource{apiPUTMethod}),
	// 	pulumi.Parent(apiResMessageProxy),
	// )

	// if err != nil {
	// 	return err
	// }

	createMethodAndIntegration := func(httpAction string) (*apigateway.Method, *apigateway.Integration, error) {
		resMethod, err := apigateway.NewMethod(
			ctx,
			fmt.Sprintf("%s-method-%s", apiName, httpAction),
			&apigateway.MethodArgs{
				HttpMethod:    pulumi.String(httpAction),
				ResourceId:    apiResMessageProxy.ID(),
				RestApi:       api.ID(),
				Authorization: pulumi.String("COGNITO_USER_POOLS"),
				AuthorizerId:  apiAuthorizer.ID(),
			},
			pulumi.Parent(apiResMessageProxy),
		)

		if err != nil {
			return nil, nil, err
		}

		resMethodIntegration, err := apigateway.NewIntegration(
			ctx,
			fmt.Sprintf("%s-lambda-integration-%s-proxy", apiName, httpAction),
			&apigateway.IntegrationArgs{
				RestApi:               api.ID(),
				ResourceId:            apiResMessageProxy.ID(),
				HttpMethod:            pulumi.String(httpAction),
				IntegrationHttpMethod: pulumi.String("POST"),
				Type:                  pulumi.String("AWS_PROXY"),
				Uri:                   &lambdaFunc.InvokeArn,
			},
			pulumi.DependsOn([]pulumi.Resource{resMethod}),
			pulumi.Parent(apiResMessageProxy),
		)

		if err != nil {
			return nil, nil, err
		}

		return resMethod, resMethodIntegration, nil
	}

	var httpMethodsRes []pulumi.Resource = make([]pulumi.Resource, 0)
	httpActions := []string{"GET", "POST", "PUT"}

	for _, action := range httpActions {
		httpRes, httpResIntegration, err := createMethodAndIntegration(action)
		if err != nil {
			return err
		}
		httpMethodsRes = append(httpMethodsRes, httpRes, httpResIntegration)
	}

	_, err = lambda.NewPermission(
		ctx,
		fmt.Sprintf("%s-lambda-permission", apiName),
		&lambda.PermissionArgs{
			Function:  lambdaFunc,
			Action:    pulumi.String("lambda:InvokeFunction"),
			Principal: pulumi.String("apigateway.amazonaws.com"),
			SourceArn: api.ExecutionArn.ApplyT(func(executionArn string) (string, error) {
				return fmt.Sprintf("%v/*/*/*", executionArn), nil
			}).(pulumi.StringOutput),
		},
	)

	if err != nil {
		return err
	}

	apiDeployment, err := apigateway.NewDeployment(
		ctx,
		fmt.Sprintf("%s-deployment", apiName),
		&apigateway.DeploymentArgs{
			RestApi:   api.ID(),
			StageName: pulumi.String("dev"),
		},
		pulumi.DependsOn(append(httpMethodsRes, apiRes)),
		pulumi.Parent(api))

	if err != nil {
		return err
	}

	_, err = apigateway.NewStage(
		ctx,
		fmt.Sprintf("%s-stage", apiName),
		&apigateway.StageArgs{
			RestApi:    api.ID(),
			Deployment: apiDeployment.ID(),
			StageName:  pulumi.String("dev"),
		},
		pulumi.Parent(apiDeployment),
	)

	if err != nil {
		return err
	}

	return nil
}

func createLambda(ctx *pulumi.Context) (*lambda.Function, error) {

	lambdaName := fmt.Sprintf("%s-lambda", getAppPrefixName(ctx))
	iamRoleName := fmt.Sprintf("%s-lambda-iam-role", getAppPrefixName(ctx))
	lambdaPolicy := `{
  "Version": "2012-10-17",
  "Statement": [
    {
	"Action": "sts:AssumeRole",
	"Principal": {
		"Service": "lambda.amazonaws.com"
	},
    "Effect": "Allow",
    "Sid": ""
    }
  ]
}
`
	logPolicy := `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*",
      "Effect": "Allow"
    }
  ]
}
`

	iamRole, err := iam.NewRole(ctx, iamRoleName, &iam.RoleArgs{
		Name:             pulumi.String(iamRoleName),
		AssumeRolePolicy: pulumi.Any(lambdaPolicy),
	})

	if err != nil {
		return nil, err
	}

	cloudWatch, err := cloudwatch.NewLogGroup(
		ctx,
		fmt.Sprintf("/aws/lambda/%s", lambdaName),
		&cloudwatch.LogGroupArgs{
			RetentionInDays: pulumi.Int(7),
		})

	if err != nil {
		return nil, err
	}

	lambdaLogPolicy, err := iam.NewPolicy(
		ctx,
		fmt.Sprintf("%s-lambda-log-policy", lambdaName),
		&iam.PolicyArgs{
			Path:        pulumi.String("/"),
			Description: pulumi.String(fmt.Sprintf("IAM policy for logging from %s", lambdaName)),
			Policy:      pulumi.Any(logPolicy),
		})

	if err != nil {
		return nil, err
	}

	lambdaLogPolicyAttachment, err := iam.NewRolePolicyAttachment(
		ctx,
		fmt.Sprintf("%s-lambda-log-policy-attachement", lambdaName),
		&iam.RolePolicyAttachmentArgs{
			Role:      iamRole.Name,
			PolicyArn: lambdaLogPolicy.Arn,
		})
	if err != nil {
		return nil, err
	}

	lambdaFunc, err := lambda.NewFunction(ctx, lambdaName, &lambda.FunctionArgs{
		Name:    pulumi.String(lambdaName),
		Role:    iamRole.Arn,
		Handler: pulumi.String("main"),
		Runtime: pulumi.String("go1.x"),
		Code:    pulumi.NewFileArchive("./lambdabin/main.zip"),
		Environment: &lambda.FunctionEnvironmentArgs{
			Variables: pulumi.ToStringMap(map[string]string{
				"TEST": "ciao",
			}),
		},
	},
		pulumi.DependsOn([]pulumi.Resource{lambdaLogPolicyAttachment, cloudWatch}),
	)

	if err != nil {
		return nil, err
	}

	return lambdaFunc, nil

}
